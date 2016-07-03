#!/usr/bin/env python
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import time
import logging
import argparse

logging.basicConfig(level=logging.INFO)
log = logging.getLogger()

sys.path.insert(0, os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.database import TASK_FAILED_PROCESSING, TASK_REPORTED
from lib.cuckoo.core.plugins import RunProcessing, RunSignatures, RunReporting
from lib.cuckoo.core.startup import init_modules, drop_privileges

def process(target=None, copy_path=None, task=None):
    results = RunProcessing(task=task).run()
    RunSignatures(results=results).run()
    RunReporting(task=task, results=results).run()

    if cfg.cuckoo.delete_original and os.path.exists(target):
        os.unlink(target)

    if cfg.cuckoo.delete_bin_copy and copy_path and os.path.exists(copy_path):
        os.unlink(copy_path)

def instance(instance):
    maxcount = cfg.cuckoo.max_analysis_count
    count = 0
    db = Database()

    # There's a good chance MySQL also works, though.
    if db.engine.name != "postgresql":
        sys.exit("Due to SQL limitations utils/process2.py currently only "
                 "supports PostgreSQL.")

    try:
        while not maxcount or count != maxcount:
            task_id = db.processing_get_task(instance)

            # Wait a small while before trying to fetch a new task.
            if task_id is None:
                time.sleep(1)
                continue

            task = db.view_task(task_id)

            log.info("Task #%d: reporting task", task.id)

            if task.category == "file":
                sample = db.view_sample(task.sample_id)

                copy_path = os.path.join(
                    CUCKOO_ROOT, "storage", "binaries", sample.sha256
                )
            else:
                copy_path = None

            try:
                process(task.target, copy_path, task=task.to_dict())
                db.set_status(task.id, TASK_REPORTED)
            except Exception as e:
                log.exception("Task #%d: error reporting: %s", task.id, e)
                db.set_status(task.id, TASK_FAILED_PROCESSING)
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

    try:
        # Run the instance.
        instance(args.instance)
    except KeyboardInterrupt:
        log.info("Interrupted by ^C.")
    except Exception:
        log.exception("Unknown exception!")

if __name__ == "__main__":
    cfg = Config()

    try:
        main()
    except KeyboardInterrupt:
        pass
