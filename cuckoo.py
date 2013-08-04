#!/usr/bin/env python
# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys
import logging
import argparse

try:
    from lib.cuckoo.common.logo import logo
    from lib.cuckoo.common.constants import CUCKOO_VERSION
    from lib.cuckoo.common.exceptions import CuckooCriticalError, CuckooDependencyError
    from lib.cuckoo.core.startup import *
    from lib.cuckoo.core.scheduler import Scheduler
    from lib.cuckoo.core.resultserver import Resultserver
except (CuckooDependencyError, ImportError) as e:
    sys.exit("ERROR: Missing dependency: {0}".format(e))

log = logging.getLogger()

def main():
    logo()
    check_working_directory()
    check_configs()
    check_version()
    create_structure()

    parser = argparse.ArgumentParser()
    parser.add_argument("-q", "--quiet", help="Display only error messages", action="store_true", required=False)
    parser.add_argument("-d", "--debug", help="Display debug messages", action="store_true", required=False)
    parser.add_argument("-m", "--memory_debug", help="Use pympler to track memory usage", action="store_true", required=False)
    parser.add_argument("-v", "--version", action="version", version="You are running Cuckoo Sandbox %s" % CUCKOO_VERSION)
    parser.add_argument("-a", "--artwork", help="Show artwork", action="store_true", required=False)
    args = parser.parse_args()

    if args.artwork:
        import time
        try:
            while True:
                time.sleep(1)
                logo()
        except KeyboardInterrupt:
            return

    init_logging()

    if args.quiet:
        log.setLevel(logging.WARN)
    elif args.debug:
        log.setLevel(logging.DEBUG)
    if args.memory_debug:
        try:
            from pympler import tracker
        except ImportError:
            sys.exit("ERROR: Missing dependency: pympler")
        memory_tracker = tracker.SummaryTracker()
        print("Starting")
        memory_tracker.print_diff()

    init_modules()
    init_tasks()

    if args.memory_debug:
        print("After init")
        memory_tracker.print_diff()
    Resultserver()

    try:
        sched = Scheduler()
        if args.memory_debug:
            print("After scheduler")
            memory_tracker.print_diff()
        sched.start()
    except KeyboardInterrupt:
        if args.memory_debug:
            print("After keyboard interrupt")
            memory_tracker.print_diff()
        sched.stop()
    finally:
        if args.memory_debug:
            print("Finally")
            memory_tracker.print_diff()

if __name__ == "__main__":
    try:
        main()
    except CuckooCriticalError as e:
        message = "%s: %s" % (e.__class__.__name__, e)
        if len(log.handlers) > 0:
            log.critical(message)
        else:
            sys.stderr.write("%s\n" % message)

        sys.exit(1)
