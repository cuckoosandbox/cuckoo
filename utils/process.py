#!/usr/bin/env python
# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import logging
import argparse

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger()

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.startup import init_modules
from lib.cuckoo.core.database import Database, TASK_REPORTED
from lib.cuckoo.core.plugins import RunProcessing, RunSignatures, RunReporting

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("id", type=str, help="ID of the analysis to process")
    parser.add_argument("-r", "--report", help="Re-generate report", action="store_true", required=False)
    args = parser.parse_args()

    init_modules()

    results = RunProcessing(task_id=args.id).run()
    RunSignatures(results=results).run()

    if args.report:
        RunReporting(task_id=args.id, results=results).run()
        Database().set_status(args.id, TASK_REPORTED)

    for proc in results["behavior"]["processes"]:
        log.debug("Process %d (%s) log parsed %d times.",
                  proc["process_id"],
                  proc["process_name"],
                  proc["calls"].parsecount)

if __name__ == "__main__":
    main()
