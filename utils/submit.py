#!/usr/bin/env python
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import logging
import argparse

logging.basicConfig()

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.colors import *
from lib.cuckoo.core.database import Database

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", type=str, help="URL, path to the file or folder to analyze")
    parser.add_argument("--url", action="store_true", default=False, help="Specify whether the target is an URL", required=False)
    parser.add_argument("--package", type=str, action="store", default="", help="Specify an analysis package", required=False)
    parser.add_argument("--custom", type=str, action="store", default="", help="Specify any custom value", required=False)
    parser.add_argument("--timeout", type=int, action="store", default=0, help="Specify an analysis timeout", required=False)
    parser.add_argument("--options", type=str, action="store", default="", help="Specify options for the analysis package (e.g. \"name=value,name2=value2\")", required=False)
    parser.add_argument("--priority", type=int, action="store", default=1, help="Specify a priority for the analysis represented by an integer", required=False)
    parser.add_argument("--machine", type=str, action="store", default="", help="Specify the identifier of a machine you want to use", required=False)
    parser.add_argument("--platform", type=str, action="store", default="", help="Specify the operating system platform you want to use (windows/darwin/linux)", required=False)
    parser.add_argument("--memory", action="store_true", default=False, help="Enable to take a memory dump of the analysis machine", required=False)
    parser.add_argument("--enforce-timeout", action="store_true", default=False, help="Enable to force the analysis to run for the full timeout period", required=False)

    try:
        args = parser.parse_args()
    except IOError as e:
        parser.error(e)
        return False

    db = Database()

    # Try to get input as utf-8.
    try:
        target = args.target.decode("utf-8")
    except UnicodeEncodeError:
        target = args.target

    if args.url:
        task_id = db.add_url(target,
                             package=args.package,
                             timeout=args.timeout,
                             options=args.options,
                             priority=args.priority,
                             machine=args.machine,
                             platform=args.platform,
                             custom=args.custom,
                             memory=args.memory,
                             enforce_timeout=args.enforce_timeout)

        print(bold(green("Success")) + ": URL \"%s\" added as task with ID %d" % (target, task_id))
    else:
        # Get absolute path to deal with relative.
        path = os.path.abspath(target)

        if not os.path.exists(path):
            print(bold(red("Error")) + ": the specified file/folder does not exist at path \"%s\"" % path)
            return False

        files = []
        if os.path.isdir(path):
            for dirname, dirnames, filenames in os.walk(path):
                for file_name in filenames:
                    file_path = os.path.join(dirname, file_name)

                    if os.path.isfile(file_path):
                        files.append(file_path)
        else:
            files.append(path)

        for file_path in files:
            task_id = db.add_path(file_path=file_path,
                                  package=args.package,
                                  timeout=args.timeout,
                                  options=args.options,
                                  priority=args.priority,
                                  machine=args.machine,
                                  platform=args.platform,
                                  custom=args.custom,
                                  memory=args.memory,
                                  enforce_timeout=args.enforce_timeout)

            if task_id:
                print(bold(green("Success")) + ": File \"%s\" added as task with ID %d" % (file_path, task_id))
            else:
                print(bold(red("Error")) + ": adding task to database")

if __name__ == "__main__":
    main()
