# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import logging
import os
import shutil
import sys
import traceback

import cuckoo
from cuckoo.common.exceptions import CuckooCriticalError
from cuckoo.common.colors import yellow, red
from cuckoo.common.logo import logo
from cuckoo.common.utils import exception_message
from cuckoo.core.database import Database
from cuckoo.core.resultserver import ResultServer
from cuckoo.core.scheduler import Scheduler
from cuckoo.core.startup import check_configs
from cuckoo.core.startup import check_version, create_structure
from cuckoo.core.startup import cuckoo_clean, drop_privileges
from cuckoo.core.startup import init_logging, init_modules
from cuckoo.core.startup import init_tasks, init_yara, init_binaries
from cuckoo.core.startup import init_rooter, init_routing
from cuckoo.misc import cwd, set_cwd, fetch_community

log = logging.getLogger("cuckoo")

def cuckoo_create():
    """Create a new Cuckoo Working Directory."""

    print "="*71
    print " "*4, yellow(
        "Welcome to Cuckoo Sandbox, this appears to be your first run!"
    )
    print " "*4, "We will now set you up with our default configuration."
    print " "*4, "You will be able to modify the configuration to your likings "
    print " "*4, "by exploring the", red(cwd()), "directory."
    print "="*71
    print

    if not os.path.isdir(cwd()):
        os.mkdir(cwd())

    dirpath = os.path.join(cuckoo.__path__[0], "data")
    for filename in os.listdir(dirpath):
        filepath = os.path.join(dirpath, filename)
        if os.path.isfile(filepath):
            shutil.copy(filepath, cwd(filename))
        else:
            shutil.copytree(filepath, cwd(filename), symlinks=True)

def cuckoo_init():
    """Initialize Cuckoo configuration.
    @param quiet: enable quiet mode.
    @param debug: enable debug mode.
    """
    logo()

    # It would appear this is the first time Cuckoo is being run (on this
    # Cuckoo Working Directory anyway).
    if not os.path.isdir(cwd()) or not os.listdir(cwd()):
        cuckoo_create()

    check_configs()
    check_version()
    create_structure()

    init_logging()

    Database().connect()

    init_modules()
    init_tasks()
    init_yara()
    init_binaries()
    init_rooter()
    init_routing()

    ResultServer()

def cuckoo_main(max_analysis_count=0):
    """Cuckoo main loop.
    @param max_analysis_count: kill cuckoo after this number of analyses
    """
    try:
        sched = Scheduler(max_analysis_count)
        sched.start()
    except KeyboardInterrupt:
        sched.stop()

def cuckoo_community():
    """Utility to fetch supplies from the Cuckoo Community."""
    fetch_community()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", nargs="?", help="Run a subcommand")
    parser.add_argument("-q", "--quiet", help="Display only error messages", action="store_true", required=False)
    parser.add_argument("-d", "--debug", help="Display debug messages", action="store_true", required=False)
    parser.add_argument("--user", type=str, help="Drop user privileges to this user")
    parser.add_argument("--root", type=str, default="~/.cuckoo", help="Cuckoo Working Directory")
    args = parser.parse_args()

    set_cwd(os.path.expanduser(args.root))

    if args.quiet:
        logging.basicConfig(level=logging.WARN)
    elif args.debug:
        logging.basicConfig(level=logging.DEBUG)

    if args.user:
        drop_privileges(args.user)

    if args.command == "clean":
        cuckoo_clean()
        sys.exit(0)

    if args.command == "community":
        cuckoo_community()
        sys.exit(0)

    try:
        cuckoo_init()
        cuckoo_main(max_analysis_count=args.max_analysis_count)
    except CuckooCriticalError as e:
        message = "{0}: {1}".format(e.__class__.__name__, e)
        if len(log.handlers):
            log.critical(message)
        else:
            sys.stderr.write("{0}\n".format(message))
        sys.exit(1)
    except:
        # Deal with an unhandled exception.
        message = exception_message()
        print message, traceback.format_exc()
