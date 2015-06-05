# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import logging
import multiprocessing
import os.path
import signal
import sys
import threading
import time

from flask import json, g
from distributed.api import node_status, submit_task, fetch_tasks
from distributed.api import store_report, delete_task
from distributed.db import db, Node, Task, NodeStatus

log = logging.getLogger(__name__)

def nullcallback(arg):
    return arg

def init_worker():
    """Have the workers ignore interrupt signals from the parent."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)

class SchedulerThread(threading.Thread):
    def __init__(self, app_context):
        threading.Thread.__init__(self)

        self.app_context = app_context
        self.available = {}

    def _mark_available(self, name):
        """Mark a node as available for scheduling."""
        self.available[name] = g.interval

        log.debug("Logging node %s as available..", name)

    def _mark_available_layer(self, name):
        """Extra layer before marking a node available for scheduling."""
        self.m.apply_async(nullcallback, args=(name,),
                           callback=self._mark_available)

    def _node_status(self, (name, status)):
        if status is None:
            log.warning("It appears node %s is unreachable!", name)
            self._mark_available(name)
            return

        # Include the timestamp of when we retrieved this status.
        status["timestamp"] = int(time.time())

        g.statuses[name] = status

        node = Node.query.filter_by(name=name).first()

        # Add this node status to the database for monitoring purposes.
        ns = NodeStatus(node.id, datetime.datetime.now(), json.dumps(status))
        db.session.add(ns)
        db.session.commit()

        log.debug("Node %s status %s", name, status)

        if not status:
            self._mark_available(name)
            return

        if status["tasks"]["pending"] < g.batch_size:
            self.submit_tasks(name, g.batch_size)

        args = node.name, node.url, "reported"
        self.m.apply_async(fetch_tasks, args=args,
                           callback=self._fetch_reports_and_mark_available)

    def _task_identifier(self, (task_id, api_task_id)):
        t = Task.query.get(task_id)
        t.task_id = api_task_id
        db.session.commit()

        log.debug("Node %s task %d -> %d", t.node_id, t.task_id, t.id)

    def _fetch_reports_and_mark_available(self, (name, tasks)):
        node = Node.query.filter_by(name=name).first()

        # Only fetch reports and mark the node as available if the
        # scheduler is still running.
        if not g.running:
            log.debug("Not fetching reports from node %s as we're exiting.",
                      name)
            return

        for task in tasks:
            q = Task.query.filter_by(node_id=node.id, task_id=task["id"])
            t = q.first()

            if t is None:
                log.debug("Node %s task #%d has not been submitted "
                          "by us!", name, task["id"])
                args = node.name, node.url, task["id"]
                self.m.apply_async(delete_task, args=args)
                continue

            dirpath = os.path.join(g.reports_directory, "%d" % t.id)

            if not os.path.isdir(dirpath):
                os.makedirs(dirpath)

            # Fetch each requested report format, request this report.
            for report_format in g.report_formats:
                args = [
                    node.name, node.url, t.task_id,
                    report_format, dirpath,
                ]
                self.m.apply_async(store_report, args=args,
                                   callback=self._store_report)

            t.status = Task.FINISHED
            t.started = datetime.datetime.strptime(task["started_on"],
                                                   "%Y-%m-%d %H:%M:%S")
            t.completed = datetime.datetime.now()

        db.session.commit()

        # Mark as available after all stuff has happened.
        self.m.apply_async(nullcallback, args=(name,),
                           callback=self._mark_available_layer)

    def _store_report(self, (name, task_id, report_format)):
        node = Node.query.filter_by(name=name).first()

        # Delete the task and all its associated files.
        args = node.name, node.url, task_id
        self.m.apply_async(delete_task, args=args)

    def submit_tasks(self, name, count):
        """Submit count tasks to a Cuckoo node."""
        # TODO Handle priority other than 1.
        # TODO Select only the tasks with appropriate tags selection.

        # Select tasks that have already been selected for this node, but have
        # not been submitted due to an unexpected exit of the program or so.
        # TODO Revive this code. Since task_id is assigned asynchronously,
        # make sure this doesn't introduce problems.
        # tasks = Task.query.filter_by(node_id=node.id, task_id=None)

        node = Node.query.filter_by(name=name).first()

        # Select tasks, order by priority.
        tasks = Task.query.filter_by(status=Task.PENDING)
        tasks = tasks.order_by(Task.priority.desc())
        tasks = tasks.order_by(Task.id).limit(count)

        # Update all tasks to use our node id.
        for task in tasks.all():
            task.node_id = node.id
            task.status = Task.PROCESSING
            task.delegated = datetime.datetime.now()
            args = node.name, node.url, task.to_dict()
            self.m.apply_async(submit_task, args=args,
                               callback=self._task_identifier)

        # Commit these changes.
        db.session.commit()

    def handle_node(self, node):
        if node.name not in self.available:
            self.available[node.name] = 1
            log.info("Detected Cuckoo node '%s': %s", node.name, node.url)

        # This node is currently being processed.
        if not self.available[node.name]:
            log.debug("Node is currently processing: %s", node.name)
            return

        # Decrease waiting time by one second.
        self.available[node.name] -= 1

        # If available returns 0 for this node then it's time to
        # schedule this node again.
        if not self.available[node.name]:
            self.m.apply_async(node_status, args=(node.name, node.url),
                               callback=self._node_status)
        else:
            log.debug("Node waiting (%d): %s..",
                      self.available[node.name], node.name)

    def _enter_app_context(self, arg):
        """The asynchronous callback calling thread also has to initialize
        the app context."""
        self.app_context.push()

    def run(self):
        self.app_context.push()
        self.m = multiprocessing.Pool(processes=g.worker_processes,
                                      initializer=init_worker,
                                      maxtasksperchild=1000)

        # Enter app context in the asynchronous callback calling thread.
        r = self.m.apply_async(nullcallback, args=(None,),
                               callback=self._enter_app_context)
        r.wait()

        while g.running:
            # We resolve the nodes every iteration, that way new nodes may
            # be added on-the-fly.
            for node in Node.query.filter_by(enabled=True).all():
                self.handle_node(node)

            time.sleep(1)

        # Print status update so the user gets an approximate of the
        # remaining work (shouldn't be much more than a few dozen seconds).
        while self.m._taskqueue.qsize():
            print "\rWaiting for worker threads,",
            print "%d remaining tasks.." % self.m._taskqueue.qsize(),
            sys.stdout.flush()
            time.sleep(0.1)

        self.m.close()
        self.m.join()
        self.app_context.pop()
