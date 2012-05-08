#!/usr/bin/env python
import sys
import logging
import argparse

from lib.cuckoo.common.logo import logo
from lib.cuckoo.common.exceptions import CuckooError
from lib.cuckoo.core.startup import *
from lib.cuckoo.core.scheduler import Scheduler

log = logging.getLogger()

def main():
    logo()
    check_dependencies()
    check_working_directory()
    create_structure()
    init_logging()
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-q", "--quiet", help="Display only error messages", action="store_true", required=False)
    parser.add_argument("-d", "--debug", help="Display debug messages", action="store_true", required=False)
    args = parser.parse_args()

    if args.quiet:
        log.setLevel(logging.WARN)
    elif args.debug:
        log.setLevel(logging.DEBUG)

    try:
        sched = Scheduler()
        sched.start()
    except KeyboardInterrupt:
        sched.stop()

if __name__ == "__main__":
    try:
        main()
    except CuckooError as e:
        if hasattr(e, "message"):
            message = "%s: %s" % (e.__class__.__name__, e.message)
            if len(log.handlers) > 0:
                log.critical(message)
            else:
                sys.stderr.write("%s\n" % message)
        sys.exit(1)
