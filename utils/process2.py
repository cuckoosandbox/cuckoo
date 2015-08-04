#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import time
import logging
import argparse

logging.basicConfig(level=logging.INFO)
log = logging.getLogger()

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.database import Database, TaskProcessing
from lib.cuckoo.core.database import TASK_FAILED_PROCESSING
from lib.cuckoo.core.database import TASK_REPORTED, TASK_COMPLETED
from lib.cuckoo.core.plugins import RunProcessing, RunSignatures, RunReporting
from lib.cuckoo.core.startup import init_modules, drop_privileges

def process(target=None, copy_path=None, task=None, report=False, auto=False):
    results = RunProcessing(task=task).run()
    RunSignatures(results=results).run()

    if report:
        RunReporting(task=task, results=results).run()

        if auto:
            if cfg.cuckoo.delete_original and os.path.exists(target):
                os.unlink(target)

            if cfg.cuckoo.delete_bin_copy and copy_path and \
                    os.path.exists(copy_path):
                os.unlink(copy_path)

def scheduler():
    db = Database()
    threshold = 32

    while True:
        tps = db.list_processing_tasks(None, 128)
        if not tps:
            log.info("No task processing instances available at the moment.")

        for tp in tps:
            # Subtracting one to account for the instance entry.
            count = db.count_processing_tasks(instance=tp.instance)-1
            log.debug("Scheduling for.. %s [tasks=%d]", tp.instance, count)

            if count > threshold:
                continue

            tasks = db.processing_get_new_tasks(threshold)
            for task in tasks:
                tp = TaskProcessing(task.id, tp.instance)
                db.add_processing_task(tp)

            log.debug("Assigned %d tasks to instance %s",
                      len(tasks), instance)

        time.sleep(1)

def instance(instance):
    maxcount = cfg.cuckoo.max_analysis_count
    count = 0
    db = Database()

    try:
        while not maxcount or count != maxcount:
            if maxcount:
                limit = min(maxcount - count, 32)
            else:
                limit = 32

            tps = db.list_processing_tasks(instance=instance, count=limit)

            # No new tasks, we can wait a small while before we query again
            # for new tasks.
            if not tps:
                # Just make sure this instance is still available - it is not
                # if the scheduler has been restarted. In that case there will
                # be no records at all for this processing task.
                if not db.count_processing_tasks(instance):
                    log.info("This instance (%s) is not available anymore, "
                             "stopping.", instance)
                    break

                time.sleep(1)
                continue

            for tp in tps:
                task = db.view_task(tp.task_id)
                if task.status != TASK_COMPLETED:
                    log.warning("Task #%d: status (%s) is not completed, "
                                "ignoring", task.id, task.status)
                    continue

                log.info("Task #%d: reporting task", task.id)

                if task.category == "file":
                    sample = db.view_sample(task.sample_id)

                    copy_path = os.path.join(CUCKOO_ROOT, "storage",
                                             "binaries", sample.sha256)
                else:
                    copy_path = None

                try:
                    process(task.target, copy_path, task=task.to_dict(),
                            report=True, auto=True)
                    db.set_status(task.id, TASK_REPORTED)
                except Exception as e:
                    log.exception("Task #%d: error reporting: %s", task.id, e)
                    db.set_status(task.id, TASK_FAILED_PROCESSING)

                db.delete_processing_task(tp)
    except KeyboardInterrupt:
        raise
    except Exception as e:
        log.exception("Caught unknown exception: %s", e)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("instance", type=str, help="Task processing instance.")
    parser.add_argument("-d", "--debug", help="Display debug messages", action="store_true", required=False)
    parser.add_argument("-u", "--user", type=str, help="Drop user privileges to this user")
    parser.add_argument("-m", "--modules", help="Path to signature and reporting modules - overrides default modules path.", type=str, required=False)
    args = parser.parse_args()

    if args.user:
        drop_privileges(args.user)

    if args.debug:
        log.setLevel(logging.DEBUG)

    if args.modules:
        sys.path.insert(0, args.modules)

    init_modules()

    db = Database()

    if args.instance == "scheduler":
        # When restarting the scheduler, we first stop all currently running
        # nodes, so to reset the state. This will then stop the instances and
        # they will be restarted by Upstart.
        for tp in db.list_processing_tasks(None, 128):
            db.delete_processing_task(tp)

        scheduler()
    else:
        # Register this instance.
        tp = TaskProcessing(None, args.instance)
        Database().add_processing_task(tp)

        try:
            # Run the instance.
            instance(args.instance)
        except Exception as e:
            log.exception("Keyboard Interrupt? -> %s", e)

        # Unregister the instance.
        Database().delete_processing_task(tp)

if __name__ == "__main__":
    cfg = Config()

    try:
        main()
    except KeyboardInterrupt:
        pass
