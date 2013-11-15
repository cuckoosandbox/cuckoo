#!/usr/bin/env python
# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import fnmatch
import logging
import os
import random
import sys

logging.basicConfig()

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.colors import bold, green, red, yellow
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import to_unicode
from lib.cuckoo.core.database import Database

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", type=str,
                        help="URL, path to the file or folder to analyze")
    parser.add_argument("--url", action="store_true", default=False,
                        help="Specify whether the target is an URL",
                        required=False)
    parser.add_argument("--package", type=str, action="store", default="",
                        help="Specify an analysis package", required=False)
    parser.add_argument("--custom", type=str, action="store", default="",
                        help="Specify any custom value", required=False)
    parser.add_argument("--timeout", type=int, action="store", default=0,
                        help="Specify an analysis timeout", required=False)
    parser.add_argument("--options", type=str, action="store", default="",
                        help="Specify options for the analysis package "
                             "(e.g. \"name=value,name2=value2\")",
                        required=False)
    parser.add_argument("--priority", type=int, action="store", default=1,
                        help="Specify a priority for the analysis "
                             "represented by an integer",
                        required=False)
    parser.add_argument("--machine", type=str, action="store", default="",
                        help="Specify the identifier of a machine you "
                             "want to use",
                        required=False)
    parser.add_argument("--platform", type=str, action="store", default="",
                        help="Specify the operating system platform you "
                             "want to use (windows/darwin/linux)",
                        required=False)
    parser.add_argument("--memory", action="store_true", default=False,
                        help="Enable to take a memory dump of the "
                             "analysis machine",
                        required=False)
    parser.add_argument("--enforce-timeout", action="store_true",
                        default=False,
                        help="Enable to force the analysis to run for the "
                             "full timeout period",
                        required=False)
    parser.add_argument("--clock", type=str, action="store", default=None,
                        help="Set virtual machine clock", required=False)
    parser.add_argument("--tags", type=str, action="store", default=None,
                        help="Specify tags identifier of a machine you "
                             "want to use",
                        required=False)
    parser.add_argument("--max", type=int, action="store", default=None,
                        help="Maximum samples to add in a row",
                        required=False)
    parser.add_argument("--pattern", type=str, action="store", default=None,
                        help="Pattern of files to submit", required=False)
    parser.add_argument("--shuffle", action="store_true", default=False,
                        help="Shuffle samples before submitting them",
                        required=False)
    parser.add_argument("--unique", action="store_true", default=False,
                        help="Only submit new samples, ignore duplicates",
                        required=False)

    try:
        args = parser.parse_args()
    except IOError as e:
        parser.error(e)
        return False

    db = Database()

    target = to_unicode(args.target)

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
                             enforce_timeout=args.enforce_timeout,
                             clock=args.clock,
                             tags=args.tags)

        if task_id:
            msg = ": URL \"{0}\" added as task with ID {1}".format(target,
                                                                   task_id)
            print(bold(green("Success")) + msg)
        else:
            print(bold(red("Error")) + ": adding task to database")	
    else:
        # Get absolute path to deal with relative.
        path = to_unicode(os.path.abspath(target))

        if not os.path.exists(path):
            msg = ": the specified file/folder does not exist " \
                  "at path \"{0}\"".format(path)
            print(bold(red("Error")) + msg)
            return False

        files = []
        if os.path.isdir(path):
            for dirname, dirnames, filenames in os.walk(path):
                for file_name in filenames:
                    file_path = os.path.join(dirname, file_name)

                    if os.path.isfile(file_path):
                        if args.pattern:
                            if fnmatch.fnmatch(file_name, args.pattern):
                                files.append(to_unicode(file_path))
                        else:
                            files.append(to_unicode(file_path))
        else:
            files.append(path)

        if args.shuffle:
            random.shuffle(files)

        for file_path in files:
            if args.unique:
                sha256 = File(file_path).get_sha256()
                if not db.find_sample(sha256=sha256) is None:
                    msg = ": Sample {0}".format(file_path)
                    print(bold(yellow("Duplicate")) + msg)
                    continue

            if not args.max is None:
                # Break if the maximum number of samples has been reached.
                if not args.max:
                    break

                args.max -= 1

            task_id = db.add_path(file_path=file_path,
                                  package=args.package,
                                  timeout=args.timeout,
                                  options=args.options,
                                  priority=args.priority,
                                  machine=args.machine,
                                  platform=args.platform,
                                  custom=args.custom,
                                  memory=args.memory,
                                  enforce_timeout=args.enforce_timeout,
                                  clock=args.clock,
                                  tags=args.tags)

            if task_id:
                msg = ": File \"{0}\" added as task with " \
                      "ID {1}".format(file_path, task_id)
                print(bold(green("Success")) + msg)
            else:
                print(bold(red("Error")) + ": adding task to database")

if __name__ == "__main__":
    main()