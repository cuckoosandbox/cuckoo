#!/usr/bin/env python
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import datetime
import logging
import os.path
import time

import settings

from distributed.api import node_status, fetch_tasks, delete_task
from distributed.api import store_report, submit_task, fetch_pcap
from distributed.app import create_app
from distributed.db import db, Task, Node, NodeStatus
from distributed.exception import InvalidReport

def scheduler():
    while True:
        for node in Node.query.filter_by(enabled=True, mode="normal").all():
            # Fetch the status of this node.
            status = node_status(node.url)
            if not status:
                log.debug("Error retrieving status of node %s", node.name)
                time.sleep(settings.interval)
                continue

            # Check whether this node still has enough samples to work with.
            if status["tasks"]["pending"] >= settings.threshold:
                continue

            # Schedule new samples for this node.
            q = Task.query.filter_by(status=Task.PENDING)
            tasks = q.limit(settings.threshold).all()
            for task in tasks:
                task.status = Task.ASSIGNED
                task.node_id = node.id

            if tasks:
                log.debug("Assigned %d tasks to %s", len(tasks), node.name)

            db.session.commit()

        time.sleep(10)

def status_caching():
    def fetch_stats(tasks):
        return dict(
            pending=tasks.filter_by(status=Task.PENDING).count(),
            processing=tasks.filter_by(status=Task.PROCESSING).count(),
            finished=tasks.filter_by(status=Task.FINISHED).count(),
            deleted=tasks.filter_by(status=Task.DELETED).count(),
        )

    while True:
        yesterday = datetime.datetime.now() - datetime.timedelta(1)
        today = Task.query.filter(Task.completed > yesterday)

        status = {
            "all": fetch_stats(Task.query),
            "prio1": fetch_stats(Task.query.filter_by(priority=1)),
            "prio2": fetch_stats(Task.query.filter_by(priority=2)),
            "today": fetch_stats(today),
            "today1": fetch_stats(today.filter_by(priority=1)),
            "today2": fetch_stats(today.filter_by(priority=2)),
        }

        ns = NodeStatus("dist.scheduler", datetime.datetime.now(), status)
        db.session.add(ns)
        db.session.commit()

        time.sleep(30)

def handle_node(instance):
    node = Node.query.filter_by(name=instance).first()
    if not node:
        log.critical("Node not found: %s", instance)
        return

    while True:
        # Fetch the status of this node.
        status = node_status(node.url)
        if not status:
            log.debug("Error retrieving status of node %s", node.name)
            time.sleep(settings.interval)
            continue

        # Include the timestamp of when we retrieved this status.
        status["timestamp"] = int(time.time())

        # Add this node status to the database for monitoring purposes.
        ns = NodeStatus(node.name, datetime.datetime.now(), status)
        db.session.add(ns)
        db.session.commit()

        # Submission of new tasks.
        if status["tasks"]["pending"] < settings.threshold:
            q = Task.query.filter_by(node_id=node.id, status=Task.ASSIGNED)
            q = q.order_by(Task.priority.desc(), Task.id)
            tasks = q.limit(settings.threshold).all()
            for t in tasks:
                t.task_id = submit_task(node.url, t.to_dict())
                t.status = Task.PROCESSING
                t.delegated = datetime.datetime.now()

            log.debug("Submitted %d tasks to %s", len(tasks), node.name)
            db.session.commit()

        # Fetching of reports.
        tasks = fetch_tasks(node.url, status="reported")
        for task in tasks[:settings.threshold]:
            # In the case that a Cuckoo node has been reset over time it's
            # possible that there are multiple combinations of
            # node-id/task-id, in this case we take the last one available.
            # (This makes it possible to re-setup a Cuckoo node).
            q = Task.query.filter_by(node_id=node.id, task_id=task["id"])
            t = q.order_by(Task.id.desc()).first()

            if t is None:
                log.debug("Node %s task #%d has not been submitted "
                          "by us!", instance, task["id"])

                # Should we delete this task? Improve through the usage of
                # the "owner" parameter.
                delete_task(node.url, task["id"])
                continue

            dirpath = os.path.join(settings.reports_directory, "%d" % t.id)
            if not os.path.isdir(dirpath):
                os.makedirs(dirpath)

            # Fetch each report.
            for report_format in settings.report_formats:
                try:
                    store_report(node.url, t.task_id, report_format, dirpath)
                except InvalidReport as e:
                    log.critical("Error fetching report: %s", e)

            # Fetch the pcap file.
            if settings.pcap:
                pcap_path = os.path.join(dirpath, "dump.pcap")
                fetch_pcap(node.url, t.task_id, pcap_path)

            # Delete the task and all its associated files from the
            # Cuckoo node.
            delete_task(node.url, t.task_id)

            t.status = Task.FINISHED
            t.started = datetime.datetime.strptime(task["started_on"],
                                                   "%Y-%m-%d %H:%M:%S")
            t.completed = datetime.datetime.now()

        log.debug("Fetched %d reports from %s", len(tasks), node.name)

        db.session.commit()
        time.sleep(settings.interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("instance", type=str, help="Name of this node instance.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbosity for debug information.")
    args = parser.parse_args()

    app = create_app()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    log = logging.getLogger("dist-%s" % args.instance)

    with app.app_context():
        if args.instance == "dist.scheduler":
            scheduler()
        elif args.instance == "dist.status":
            status_caching()
        else:
            handle_node(args.instance)
