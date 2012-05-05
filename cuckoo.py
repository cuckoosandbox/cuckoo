#!/usr/bin/env python
import logging
import argparse

from lib.cuckoo.common.logo import logo
from lib.cuckoo.core.startup import check_python_version, check_dependencies, create_structure, check_working_directory, init_logging
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
    except SystemExit as e:
        if type(e.message) == str:
            log.critical(e.message)
