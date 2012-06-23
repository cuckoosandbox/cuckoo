#!/usr/bin/env python
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import logging
import argparse

logging.basicConfig()

sys.path.append("..")

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.utils import File
from lib.cuckoo.core.database import Database

def main():
    if CUCKOO_ROOT == "." or not os.path.exists(CUCKOO_ROOT):
        print("ERROR: you need to specify a valid absolute root directory in lib/cuckoo/common/constants.py")
        return False

    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=str, help="Path to the file to analyze")
    parser.add_argument("--package", type=str, action="store", help="Specify an analysis package", required=False)
    parser.add_argument("--timeout", type=int, action="store", help="Specify an analysis timeout", required=False)
    parser.add_argument("--options", type=str, action="store", help="Specify options for the analysis package (e.g. \"name=value,name2=value2\")", required=False)
    parser.add_argument("--priority", type=int, action="store", help="Specify a priority for the analysis represented by an integer", required=False)
    parser.add_argument("--machine", type=str, action="store", help="Specify the identifier of a machine you want to use", required=False)
    parser.add_argument("--platform", type=str, action="store", help="Specify the operating system platform you want to use (windows/darwin/linux)", required=False)

    try:
        args = parser.parse_args()
    except IOError as e:
        parser.error(e.message)
        return False

    if not os.path.exists(args.path):
        print("ERROR: the specified file does not exist at path \"%s\"" % args.path)
        return False

    db = Database()

    task_id = db.add(file_path=args.path,
                     md5=File(args.path).get_md5(),
                     package=args.package,
                     timeout=args.timeout,
                     options=args.options,
                     priority=args.priority,
                     machine=args.machine,
                     platform=args.platform)

    print("SUCCESS: Task added with id %d" % task_id)

if __name__ == "__main__":
    main()
