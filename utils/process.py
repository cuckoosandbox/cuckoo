#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import time
import logging
import argparse
import signal
import multiprocessing

logging.basicConfig(level=logging.INFO)
log = logging.getLogger()

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.database import Database, TASK_REPORTED, TASK_COMPLETED
from lib.cuckoo.core.database import TASK_FAILED_PROCESSING
from lib.cuckoo.core.plugins import RunProcessing, RunSignatures, RunReporting
from lib.cuckoo.core.startup import init_modules

def process(task_id, target=None, copy_path=None, report=False, auto=False):
    assert isinstance(task_id, int)

    results = RunProcessing(task_id=task_id).run()
    RunSignatures(results=results).run()

    if report:
        RunReporting(task_id=task_id, results=results).run()
        Database().set_status(task_id, TASK_REPORTED)

        if auto:
            if cfg.cuckoo.delete_original and os.path.exists(target):
                os.unlink(target)

            if cfg.cuckoo.delete_bin_copy and os.path.exists(copy_path):
                os.unlink(copy_path)

def init_worker():
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def autoprocess(parallel=1):
    maxcount = cfg.cuckoo.max_analysis_count
    count = 0
    db = Database()
    pool = multiprocessing.Pool(parallel, init_worker)
    pending_results = []

    try:
        # CAUTION - big ugly loop ahead.
        while count < maxcount or not maxcount:

            # Pending_results maintenance.
            for ar, tid, target, copy_path in list(pending_results):
                if ar.ready():
                    if ar.successful():
                        log.info("Task #%d: reports generation completed", tid)
                    else:
                        try:
                            ar.get()
                        except:
                            log.exception("Exception when processing task ID %u.", tid)
                            db.set_status(tid, TASK_FAILED_PROCESSING)

                    pending_results.remove((ar, tid, target, copy_path))

            # If still full, don't add more (necessary despite pool).
            if len(pending_results) >= parallel:
                time.sleep(5)
                continue

            # If we're here, getting parallel tasks should at least
            # have one we don't know.
            tasks = db.list_tasks(status=TASK_COMPLETED, limit=parallel,
                                  order_by="completed_on asc")

            added = False
            # For loop to add only one, nice. (reason is that we shouldn't overshoot maxcount)
            for task in tasks:
                # Not-so-efficient lock.
                if task.id in [tid for ar, tid, target, copy_path
                               in pending_results]:
                    continue

                log.info("Processing analysis data for Task #%d", task.id)

                if task.category == "file":
                    sample = db.view_sample(task.sample_id)

                    copy_path = os.path.join(CUCKOO_ROOT, "storage",
                                             "binaries", sample.sha256)
                else:
                    copy_path = None

                args = int(task.id), task.target, copy_path
                kwargs = dict(report=True, auto=True)
                result = pool.apply_async(process, args, kwargs)

                pending_results.append((result, task.id, task.target, copy_path))

                count += 1
                added = True
                break

            if not added:
                # don't hog cpu
                time.sleep(5)

    except KeyboardInterrupt:
        pool.terminate()
        raise
    except:
        import traceback
        traceback.print_exc()
    finally:
        pool.join()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("id", type=str, help="ID of the analysis to process (auto for continuous processing of unprocessed tasks).")
    parser.add_argument("-d", "--debug", help="Display debug messages", action="store_true", required=False)
    parser.add_argument("-r", "--report", help="Re-generate report", action="store_true", required=False)
    parser.add_argument("-p", "--parallel", help="Number of parallel threads to use (auto mode only).", type=int, required=False, default=1)
    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)

    init_modules()

    if args.id == "auto":
        autoprocess(parallel=args.parallel)
    else:
        process(int(args.id), report=args.report)


if __name__ == "__main__":
    cfg = Config()

    try:
        main()
    except KeyboardInterrupt:
        pass
