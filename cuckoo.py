#!/usr/bin/env python
# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import logging
import argparse

try:
    from lib.cuckoo.common.logo import logo
    from lib.cuckoo.common.constants import CUCKOO_VERSION, CUCKOO_ROOT
    from lib.cuckoo.common.exceptions import CuckooCriticalError
    from lib.cuckoo.common.exceptions import CuckooDependencyError
    from lib.cuckoo.core.startup import check_working_directory, check_configs
    from lib.cuckoo.core.startup import check_version, create_structure
    from lib.cuckoo.core.startup import init_logging, init_modules, init_tasks
    from lib.cuckoo.core.scheduler import Scheduler
    from lib.cuckoo.core.resultserver import Resultserver
except (CuckooDependencyError, ImportError) as e:
    sys.exit("ERROR: Missing dependency: {0}".format(e))

log = logging.getLogger()

def cuckoo_main(quiet=False, debug=False, artwork=False, test=False):
    cur_path = os.getcwd()
    os.chdir(CUCKOO_ROOT)

    logo()
    check_working_directory()
    check_configs()
    check_version()
    create_structure()

    if artwork:
        import time
        try:
            while True:
                time.sleep(1)
                logo()
        except KeyboardInterrupt:
            return

    init_logging()

    if quiet:
        log.setLevel(logging.WARN)
    elif debug:
        log.setLevel(logging.DEBUG)

    init_modules()
    init_tasks()

    # This is just a temporary hack, we need an actual test suite to integrate
    # with Travis-CI.
    if test:
        return

    Resultserver()

    try:
        sched = Scheduler()
        sched.start()
    except KeyboardInterrupt:
        sched.stop()

    os.chdir(cur_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-q", "--quiet", help="Display only error messages", action="store_true", required=False)
    parser.add_argument("-d", "--debug", help="Display debug messages", action="store_true", required=False)
    parser.add_argument("-v", "--version", action="version", version="You are running Cuckoo Sandbox {0}".format(CUCKOO_VERSION))
    parser.add_argument("-a", "--artwork", help="Show artwork", action="store_true", required=False)
    parser.add_argument("-t", "--test", help="Test startup", action="store_true", required=False)
    args = parser.parse_args()

    try:
        cuckoo_main(quiet=args.quiet, debug=args.debug, artwork=args.artwork,
                    test=args.test)
    except CuckooCriticalError as e:
        message = "{0}: {1}".format(e.__class__.__name__, e)
        if len(log.handlers) > 0:
            log.critical(message)
        else:
            sys.stderr.write("{0}\n".format(message))

        sys.exit(1)
