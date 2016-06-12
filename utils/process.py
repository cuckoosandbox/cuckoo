#!/usr/bin/env python
# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import time
import logging
import argparse
import signal
import multiprocessing
import traceback

sys.path.insert(0, os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.database import Database, TASK_REPORTED, TASK_COMPLETED
from lib.cuckoo.core.database import Task, TASK_FAILED_PROCESSING
from lib.cuckoo.core.plugins import RunProcessing, RunSignatures, RunReporting
from lib.cuckoo.core.startup import init_modules, drop_privileges

log = None

# We keep a reporting queue with at most a few hundred entries.
QUEUE_THRESHOLD = 128

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

def process_wrapper(*args, **kwargs):
    try:
        process(*args, **kwargs)
    except Exception as e:
        e.traceback = traceback.format_exc()
        raise e

def init_worker():
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def autoprocess(parallel=1):
    maxcount = cfg.cuckoo.max_analysis_count
    count = 0
    db = Database()
    pending_results = {}

    # Respawn a worker process every 1000 tasks just in case we
    # have any memory leaks.
    pool = multiprocessing.Pool(processes=parallel, initializer=init_worker,
                                maxtasksperchild=1000)

    try:
        while True:
            # Pending results maintenance.
            for tid, ar in pending_results.items():
                if not ar.ready():
                    continue

                if ar.successful():
                    log.info("Task #%d: reports generation completed", tid)
                    db.set_status(tid, TASK_REPORTED)
                else:
                    try:
                        ar.get()
                    except Exception as e:
                        log.critical("Task #%d: exception in reports generation: %s", tid, e)
                        if hasattr(e, "traceback"):
                            log.info(e.traceback)

                    db.set_status(tid, TASK_FAILED_PROCESSING)

                pending_results.pop(tid)
                count += 1

            # Make sure our queue has plenty of tasks in it.
            if len(pending_results) >= QUEUE_THRESHOLD:
                time.sleep(1)
                continue

            # End of processing?
            if maxcount and count == maxcount:
                break

            # No need to submit further tasks for reporting as we've already
            # gotten to our maximum.
            if maxcount and count + len(pending_results) == maxcount:
                time.sleep(1)
                continue

            # Get at most queue threshold new tasks. We skip the first N tasks
            # where N is the amount of entries in the pending results list.
            # Given we update a tasks status right before we pop it off the
            # pending results list it is guaranteed that we skip over all of
            # the pending tasks in the database and no further.
            if maxcount:
                limit = maxcount - count - len(pending_results)
            else:
                limit = QUEUE_THRESHOLD

            tasks = db.list_tasks(status=TASK_COMPLETED,
                                  offset=len(pending_results),
                                  limit=min(limit, QUEUE_THRESHOLD),
                                  order_by=Task.completed_on)

            # No new tasks, we can wait a small while before we query again
            # for new tasks.
            if not tasks:
                time.sleep(5)
                continue

            for task in tasks:
                # Ensure that this task is not already in the pending list.
                # This is really mostly for debugging and should never happen.
                assert task.id not in pending_results

                log.info("Task #%d: queueing for reporting", task.id)

                if task.category == "file":
                    sample = db.view_sample(task.sample_id)

                    copy_path = os.path.join(CUCKOO_ROOT, "storage",
                                             "binaries", sample.sha256)
                else:
                    copy_path = None

                args = task.target, copy_path
                kwargs = {
                    "report": True,
                    "auto": True,
                    "task": dict(task.to_dict()),
                }
                result = pool.apply_async(process_wrapper, args, kwargs)
                pending_results[task.id] = result
    except KeyboardInterrupt:
        pool.terminate()
        raise
    except:
        log.exception("Caught unknown exception")
    finally:
        pool.join()

def main():
    global log

    parser = argparse.ArgumentParser()
    parser.add_argument("id", type=str, help="ID of the analysis to process (auto for continuous processing of unprocessed tasks).")
    parser.add_argument("-d", "--debug", help="Display debug messages", action="store_true", required=False)
    parser.add_argument("-r", "--report", help="Re-generate report", action="store_true", required=False)
    parser.add_argument("-p", "--parallel", help="Number of parallel threads to use (auto mode only).", type=int, required=False, default=1)
    parser.add_argument("-u", "--user", type=str, help="Drop user privileges to this user")
    parser.add_argument("-m", "--modules", help="Path to signature and reporting modules - overrides default modules path.", type=str, required=False)

    args = parser.parse_args()

    if args.user:
        drop_privileges(args.user)

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    log = logging.getLogger("cuckoo.process")

    if args.modules:
        sys.path.insert(0, args.modules)

    init_modules(machinery=False)

    if args.id == "auto":
        autoprocess(parallel=args.parallel)
    else:
        task = Database().view_task(int(args.id))
        if not task:
            task = {
                "id": int(args.id),
                "category": "file",
                "target": "",
                "options": "",
            }
            process(task=task, report=args.report)
        else:
            process(task=task.to_dict(), report=args.report)

if __name__ == "__main__":
    cfg = Config()

    try:
        main()
    except KeyboardInterrupt:
        pass
