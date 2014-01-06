#!/usr/bin/env python
# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import time
import logging
import argparse

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.config import Config
from lib.cuckoo.core.database import Database, TASK_REPORTED, TASK_COMPLETED
from lib.cuckoo.core.database import TASK_FAILED_PROCESSING
from lib.cuckoo.core.plugins import RunProcessing, RunSignatures, RunReporting
from lib.cuckoo.core.startup import init_modules

def do(aid, report=False):
    try:
        results = RunProcessing(task_id=aid).run()
    except Exception as e:
        log.error(e)
        return
    RunSignatures(results=results).run()

    if report:
        RunReporting(task_id=aid, results=results).run()
        Database().set_status(aid, TASK_REPORTED)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("id", type=str, help="ID of the analysis to process")
    parser.add_argument("-d", "--debug", help="Display debug messages", action="store_true", required=False)
    parser.add_argument("-r", "--report", help="Re-generate report", action="store_true", required=False)
    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)

    init_modules()

    if args.id == "auto":
        cfg = Config()
        maxcount = cfg.cuckoo.max_analysis_count
        count = 0
        db = Database()
        while count < maxcount or not maxcount:
            tasks = db.list_tasks(status=TASK_COMPLETED, limit=1)

            for task in tasks:
                log.info("Processing analysis data for Task #%d", task.id)
                try:
                    do(task.id, report=True)
                except:
                    log.exception("Exception when processing a task.")
                    db.set_status(task.id, TASK_FAILED_PROCESSING)
                else:
                    log.info("Task #%d: reports generation completed", task.id)

                count += 1

            if not tasks:
                time.sleep(5)

    else:
        try:
            task_id = int(args.id)
        except ValueError:
            log.error("Invalid task id value")
            return
        log.info("Processing analysis data for Task #%d", task_id)
        try:
            do(task_id, report=args.report)
        except:
            log.exception("Exception when processing a task.")


if __name__ == "__main__":
    main()
