#!/usr/bin/env python
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
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
except (CuckooDependencyError, ImportError) as e:
    sys.exit("ERROR: Missing dependency: %s" % e)

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

    init_modules()

    try:
        sched = Scheduler()
        sched.start()
    except KeyboardInterrupt:
        sched.stop()

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
