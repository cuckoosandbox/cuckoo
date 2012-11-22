#!/usr/bin/env python
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import logging
import argparse

logging.basicConfig(level=logging.DEBUG)

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.core.startup import init_modules
from lib.cuckoo.core.processor import Processor
from lib.cuckoo.core.reporter import Reporter

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=str, help="Path to the folder containing the analysis results to process")
    parser.add_argument("-r", "--report", help="Re-generate report", action="store_true", required=False)
    args = parser.parse_args()

    init_modules()

    results = Processor(args.path).run()
    if args.report:
        Reporter(args.path).run(results)

if __name__ == "__main__":
    main()