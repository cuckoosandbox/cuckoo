#!/usr/bin/env python
# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import fnmatch
import logging
import os
import random
import sys

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

sys.path.insert(0, os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.colors import bold, green, red, yellow
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import to_unicode
from lib.cuckoo.core.database import Database

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", type=str, nargs="?", help="URL, path to the file or folder to analyze")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--remote", type=str, action="store", default=None, help="Specify IP:port to a Cuckoo API server to submit remotely", required=False)
    parser.add_argument("--url", action="store_true", default=False, help="Specify whether the target is an URL", required=False)
    parser.add_argument("--package", type=str, action="store", default="", help="Specify an analysis package", required=False)
    parser.add_argument("--custom", type=str, action="store", default="", help="Specify any custom value", required=False)
    parser.add_argument("--owner", type=str, action="store", default="", help="Specify the task owner", required=False)
    parser.add_argument("--timeout", type=int, action="store", default=0, help="Specify an analysis timeout", required=False)
    parser.add_argument("-o", "--options", type=str, action="store", default="", help="Specify options for the analysis package (e.g. \"name=value,name2=value2\")", required=False)
    parser.add_argument("--priority", type=int, action="store", default=1, help="Specify a priority for the analysis represented by an integer", required=False)
    parser.add_argument("--machine", type=str, action="store", default="", help="Specify the identifier of a machine you want to use", required=False)
    parser.add_argument("--platform", type=str, action="store", default="", help="Specify the operating system platform you want to use (windows/darwin/linux)", required=False)
    parser.add_argument("--memory", action="store_true", default=False, help="Enable to take a memory dump of the analysis machine", required=False)
    parser.add_argument("--enforce-timeout", action="store_true", default=False, help="Enable to force the analysis to run for the full timeout period", required=False)
    parser.add_argument("--clock", type=str, action="store", default=None, help="Set virtual machine clock", required=False)
    parser.add_argument("--tags", type=str, action="store", default=None, help="Specify tags identifier of a machine you want to use", required=False)
    parser.add_argument("--baseline", action="store_true", default=None, help="Run a baseline analysis", required=False)
    parser.add_argument("--max", type=int, action="store", default=None, help="Maximum samples to add in a row", required=False)
    parser.add_argument("--pattern", type=str, action="store", default=None, help="Pattern of files to submit", required=False)
    parser.add_argument("--shuffle", action="store_true", default=False, help="Shuffle samples before submitting them", required=False)
    parser.add_argument("--unique", action="store_true", default=False, help="Only submit new samples, ignore duplicates", required=False)
    parser.add_argument("--quiet", action="store_true", default=False, help="Only print text on failure", required=False)

    try:
        args = parser.parse_args()
    except IOError as e:
        parser.error(e)
        return False

    if not args.baseline and not args.target:
        print "No file or URL has been specified!"
        exit(1)

    # If the quiet flag has been set, then we also disable the "warning"
    # level of the logging module. (E.g., when pydeep has not been installed,
    # there will be a warning message, because Cuckoo can't resolve the
    # ssdeep hash of this particular sample.)
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig()

    if args.quiet:
        logging.disable(logging.WARNING)

    db = Database()

    if args.url:
        target = to_unicode(args.target)
        if args.remote:
            if not HAVE_REQUESTS:
                print(bold(red("Error")) + ": you need to install python-requests (`pip install requests`)")
                return False

            url = "http://{0}/tasks/create/url".format(args.remote)

            data = dict(
                url=target,
                package=args.package,
                timeout=args.timeout,
                options=args.options,
                priority=args.priority,
                machine=args.machine,
                platform=args.platform,
                memory=args.memory,
                enforce_timeout=args.enforce_timeout,
                custom=args.custom,
                owner=args.owner,
                tags=args.tags
            )

            try:
                response = requests.post(url, data=data)
            except Exception as e:
                print(bold(red("Error")) + ": unable to send URL: {0}".format(e))
                return False

            json = response.json()
            task_id = json["task_id"]
        else:
            task_id = db.add_url(target,
                                 package=args.package,
                                 timeout=args.timeout,
                                 options=args.options,
                                 priority=args.priority,
                                 machine=args.machine,
                                 platform=args.platform,
                                 custom=args.custom,
                                 owner=args.owner,
                                 memory=args.memory,
                                 enforce_timeout=args.enforce_timeout,
                                 clock=args.clock,
                                 tags=args.tags)

        if task_id:
            if not args.quiet:
                print(bold(green("Success")) + u": URL \"{0}\" added as task with ID {1}".format(target, task_id))
        else:
            print(bold(red("Error")) + ": adding task to database")
    elif args.baseline:
        if args.remote:
            print "Remote baseline support has not yet been implemented."
            exit(1)

        task_id = db.add_baseline(args.timeout, args.owner, args.machine,
                                  args.memory)
        if task_id:
            if not args.quiet:
                print(bold(green("Success")) + u": Baseline analysis added as task with ID {0}".format(task_id))
        else:
            print(bold(red("Error")) + ": adding task to database")
    else:
        target = to_unicode(args.target)

        # Get absolute path to deal with relative.
        path = to_unicode(os.path.abspath(target))

        if not os.path.exists(path):
            print(bold(red("Error")) + u": the specified file/folder does not exist at path \"{0}\"".format(path))
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
        else:
            files = sorted(files)

        for file_path in files:
            if not File(file_path).get_size():
                if not args.quiet:
                    print(bold(yellow("Empty") + ": sample {0} (skipping file)".format(file_path)))

                continue

            if args.max is not None:
                # Break if the maximum number of samples has been reached.
                if not args.max:
                    break

                args.max -= 1

            if args.remote:
                if not HAVE_REQUESTS:
                    print(bold(red("Error")) + ": you need to install python-requests (`pip install requests`)")
                    return False

                url = "http://{0}/tasks/create/file".format(args.remote)

                files = dict(
                    file=open(file_path, "rb"),
                    filename=os.path.basename(file_path)
                )

                data = dict(
                    package=args.package,
                    timeout=args.timeout,
                    options=args.options,
                    priority=args.priority,
                    machine=args.machine,
                    platform=args.platform,
                    memory=args.memory,
                    enforce_timeout=args.enforce_timeout,
                    custom=args.custom,
                    owner=args.owner,
                    tags=args.tags
                )

                try:
                    response = requests.post(url, files=files, data=data)
                except Exception as e:
                    print(bold(red("Error")) + ": unable to send file: {0}".format(e))
                    return False

                json = response.json()
                task_id = json["task_id"]
            else:
                if args.unique:
                    sha256 = File(file_path).get_sha256()
                    if not db.find_sample(sha256=sha256) is None:
                        msg = ": Sample {0} (skipping file)".format(file_path)
                        if not args.quiet:
                            print(bold(yellow("Duplicate")) + msg)
                        continue

                task_id = db.add_path(file_path=file_path,
                                      package=args.package,
                                      timeout=args.timeout,
                                      options=args.options,
                                      priority=args.priority,
                                      machine=args.machine,
                                      platform=args.platform,
                                      custom=args.custom,
                                      owner=args.owner,
                                      memory=args.memory,
                                      enforce_timeout=args.enforce_timeout,
                                      clock=args.clock,
                                      tags=args.tags)

            if task_id:
                if not args.quiet:
                    print(bold(green("Success")) + u": File \"{0}\" added as task with ID {1}".format(file_path, task_id))
            else:
                print(bold(red("Error")) + ": adding task to database")

if __name__ == "__main__":
    main()
