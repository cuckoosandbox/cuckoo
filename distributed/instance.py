#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import ConfigParser
import datetime
import json
import logging
import os.path
import sys
import time

from distributed.api import node_status, fetch_tasks, delete_task
from distributed.api import store_report, submit_task
from distributed.app import create_app
from distributed.db import db, Task, Node, NodeStatus
from distributed.exception import InvalidReport

def scheduler(args):
    while True:
        for node in Node.query.filter_by(enabled=True).all():
            # Check whether this node still has enough samples to work with.
            q = Task.query.filter_by(node_id=node.id)
            q = q.filter(Task.status.in_((Task.ASSIGNED, Task.PROCESSING)))
            if q.count() >= args.threshold:
                continue

            # Schedule new samples for this node.
            q = Task.query.filter_by(status=Task.PENDING)
            tasks = q.limit(args.threshold).all()
            for task in tasks:
                task.status = Task.ASSIGNED
                task.node_id = node.id

            if tasks:
                log.debug("Assigned %d tasks to %s", len(tasks), node.name)

            db.session.commit()

        time.sleep(10)

def status_caching(args):
    pass

def handle_node(args):
    node = Node.query.filter_by(name=args.instance).first()
    if not node:
        log.critical("Node not found: %s", args.instance)
        return

    while True:
        # Fetch the status of this node.
        status = node_status(node.url)
        if not status:
            time.sleep(args.interval)
            continue

        # Include the timestamp of when we retrieved this status.
        status["timestamp"] = int(time.time())

        # Add this node status to the database for monitoring purposes.
        ns = NodeStatus(node.id, datetime.datetime.now(), json.dumps(status))
        db.session.add(ns)

        # Submission of new tasks.
        if status["tasks"]["pending"] < args.threshold:
            q = Task.query.filter_by(node_id=node.id, status=Task.ASSIGNED)
            q = q.order_by(Task.priority.desc(), Task.id)
            tasks = q.limit(args.threshold).all()
            for t in tasks:
                t.task_id = submit_task(node.url, t.to_dict())
                t.status = Task.PROCESSING
                t.delegated = datetime.datetime.now()

            if tasks:
                log.debug("Submitted %d tasks to %s", len(tasks), node.name)

        # Fetching of reports.
        tasks = fetch_tasks(node.url, status="reported")
        for task in tasks:
            q = Task.query.filter_by(node_id=node.id, task_id=task["id"])
            t = q.first()

            if t is None:
                log.debug("Node %s task #%d has not been submitted "
                          "by us!", args.instance, task["id"])

                # Should we delete this task? Improve through the usage of
                # the "owner" parameter.
                delete_task(node.url, task["id"])
                continue

            dirpath = os.path.join(args.reports_directory, "%d" % t.id)
            if not os.path.isdir(dirpath):
                os.makedirs(dirpath)

            # Fetch each report.
            for report_format in args.report_formats:
                try:
                    store_report(node.url, t.task_id, report_format, dirpath)
                except InvalidReport as e:
                    log.critical("Error fetching report: %s" % e)

            delete_task(node.url, t.task_id)

            t.status = Task.FINISHED
            t.started = datetime.datetime.strptime(task["started_on"],
                                                   "%Y-%m-%d %H:%M:%S")
            t.completed = datetime.datetime.now()

        if tasks:
            log.debug("Fetched %d reports from %s", len(tasks), node.name)

        db.session.commit()
        time.sleep(args.interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("instance", type=str, help="Name of this node instance.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbosity for debug information.")
    parser.add_argument("-s", "--settings", type=str, help="Settings file.")
    args = parser.parse_args()

    if not args.settings:
        dirpath = os.path.abspath(os.path.dirname(__file__))
        conf_path = os.path.join(dirpath, "..", "conf", "distributed.conf")
        args.settings = conf_path

    s = ConfigParser.ConfigParser()
    s.read(args.settings)

    if not s.get("distributed", "database"):
        sys.exit("Please configure a database connection.")

    args.database_connection = s.get("distributed", "database")
    args.threshold = s.getint("distributed", "threshold")
    args.interval = s.getint("distributed", "interval")
    args.reports_directory = s.get("distributed", "reports_directory")

    args.report_formats = []
    for report_format in s.get("distributed", "report_formats").split(","):
        args.report_formats.append(report_format.strip())

    if not args.report_formats:
        sys.exit("Please configure one or more reporting formats.")

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    log = logging.getLogger("dist-%s" % args.instance)

    with create_app(args.database_connection).app_context():
        if args.instance == "__scheduler__":
            scheduler(args)
        elif args.instance == "__status__":
            status_caching(args)
        else:
            handle_node(args)
