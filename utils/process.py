#!/usr/bin/env python
# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import time
import logging
import argparse
import multiprocessing

logging.basicConfig(level=logging.INFO)
log = logging.getLogger()

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.config import Config
from lib.cuckoo.core.database import Database, TASK_REPORTED, TASK_COMPLETED
from lib.cuckoo.core.database import TASK_FAILED_PROCESSING
from lib.cuckoo.core.plugins import RunProcessing, RunSignatures, RunReporting
from lib.cuckoo.core.startup import init_modules

def process(aid, report=False):
    results = RunProcessing(task_id=aid).run()
    RunSignatures(results=results).run()

    if report:
        RunReporting(task_id=aid, results=results).run()
        Database().set_status(aid, TASK_REPORTED)

def autoprocess(parallel=1):
    cfg = Config()
    maxcount = cfg.cuckoo.max_analysis_count
    count = 0
    db = Database()
    pool = multiprocessing.Pool(parallel)
    pending_results = []

    # CAUTION - big ugly loop ahead
    while count < maxcount or not maxcount:

        # pending_results maintenance
        for ar, tid in list(pending_results):
            if ar.ready():
                if ar.successful():
                    log.info("Task #%d: reports generation completed", tid)
                else:
                    try:
                        ar.get()
                    except:
                        log.exception("Exception when processing task ID %u.", tid)
                        db.set_status(tid, TASK_FAILED_PROCESSING)

                pending_results.remove((ar, tid))

        # if still full, don't add more (necessary despite pool)
        if len(pending_results) >= parallel:
            time.sleep(1)
            continue

        # if we're here, getting #parallel tasks should at least have one we don't know
        tasks = db.list_tasks(status=TASK_COMPLETED, limit=parallel)

        # for loop to add only one, nice
        for task in tasks:
            # not-so-efficient lock
            if task.id in [tid for ar, tid in pending_results]:
                continue

            log.info("Processing analysis data for Task #%d", task.id)

            result = pool.apply_async(process, (task.id,), {"report": True})
            pending_results.append((result, task.id))

            count += 1
            break

        # if there wasn't anything to add, sleep tight
        if not tasks:
            time.sleep(5)

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
        process(args.id, report=args.report)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
