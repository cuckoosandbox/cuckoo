# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import click
import logging
import os
import shutil
import sys
import traceback

import cuckoo

from cuckoo.apps import fetch_community, submit_tasks
from cuckoo.common.exceptions import CuckooCriticalError
from cuckoo.common.colors import yellow, red, green, bold
from cuckoo.common.logo import logo
from cuckoo.common.utils import exception_message
from cuckoo.core.database import Database
from cuckoo.core.resultserver import ResultServer
from cuckoo.core.scheduler import Scheduler
from cuckoo.core.startup import check_configs, init_modules
from cuckoo.core.startup import check_version, create_structure
from cuckoo.core.startup import cuckoo_clean, drop_privileges
from cuckoo.core.startup import init_logging, init_console_logging
from cuckoo.core.startup import init_tasks, init_yara, init_binaries
from cuckoo.core.startup import init_rooter, init_routing
from cuckoo.misc import cwd, set_cwd

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
    print
    print " "*4, "Among other configurable things of most interest is the"
    print " "*4, "new location for your Cuckoo configuration:"
    print " "*4, "         " + red(cwd("conf"))
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

    print "Cuckoo has finished setting up the default configuration."
    print "Please modify the default settings where required and"
    print "start Cuckoo again (by running `cuckoo` or `cuckoo -d`)."

def cuckoo_init(level):
    """Initialize Cuckoo configuration.
    @param quiet: enable quiet mode.
    @param debug: enable debug mode.
    """
    logo()

    # It would appear this is the first time Cuckoo is being run (on this
    # Cuckoo Working Directory anyway).
    if not os.path.isdir(cwd()) or not os.listdir(cwd()):
        cuckoo_create()
        sys.exit(0)

    check_configs()
    check_version()
    create_structure()

    init_logging(level)

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

@click.group(invoke_without_command=True)
@click.option("-d", "--debug", is_flag=True)
@click.option("-q", "--quiet", is_flag=True)
@click.option("-m", "--maxcount", default=0)
@click.option("--user")
@click.option("--root", envvar="CUCKOO", default="~/.cuckoo")
@click.pass_context
def main(ctx, debug, quiet, maxcount, user, root):
    # Cuckoo Working Directory precedence:
    # * Command-line option (--root)
    # * Environment option ("CUCKOO")
    # * Default value ("~/.cuckoo")
    set_cwd(os.path.expanduser(root))

    # Drop privileges.
    user and drop_privileges(user)

    # A subcommand will be invoked, so don't run Cuckoo itself.
    if ctx.invoked_subcommand:
        return

    if quiet:
        level = logging.WARN
    elif debug:
        level = logging.DEBUG
    else:
        level = logging.INFO

    try:
        cuckoo_init(level)
        cuckoo_main(maxcount)
    except CuckooCriticalError as e:
        message = "{0}: {1}".format(e.__class__.__name__, e)
        if len(log.handlers):
            log.critical(message)
        else:
            sys.stderr.write("{0}\n".format(message))
        sys.exit(1)
    except SystemExit:
        pass
    except:
        # Deal with an unhandled exception.
        message = exception_message()
        print message, traceback.format_exc()

@main.command()
@click.option("-f", "--force", is_flag=True, help="Overwrite existing files")
@click.option("-b", "--branch", default="master", help="Specify a different community branch rather than master")
@click.option("--file", "--filepath", type=click.Path(exists=True), help="Specify a local copy of a community .tar.gz file")
def community(force, branch, filepath):
    """Utility to fetch supplies from the Cuckoo Community."""
    fetch_community(force=force, branch=branch, filepath=filepath)

@main.command()
def clean():
    """Utility to clean the Cuckoo Working Directory and associated
    databases."""
    cuckoo_clean()

@main.command()
@click.argument("target", nargs=-1)
@click.option("-u", "--url", is_flag=True)
@click.option("-o", "--options")
@click.option("--package")
@click.option("--custom")
@click.option("--owner")
@click.option("--timeout", type=int)
@click.option("--priority", type=int)
@click.option("--machine")
@click.option("--platform")
@click.option("--memory", is_flag=True)
@click.option("--enforce-timeout", is_flag=True)
@click.option("--clock")
@click.option("--tags")
@click.option("--baseline", is_flag=True)
@click.option("--remote")
@click.option("--shuffle", is_flag=True)
@click.option("--pattern")
@click.option("--max", type=int)
@click.option("-d", "--debug", is_flag=True)
@click.option("-q", "--quiet", is_flag=True)
def submit(target, url, options, package, custom, owner, timeout, priority,
           machine, platform, memory, enforce_timeout, clock, tags, baseline,
           remote, shuffle, pattern, max, debug, quiet):
    """Submit one or more files or URLs to Cuckoo."""
    if quiet:
        level = logging.WARN
    elif debug:
        level = logging.DEBUG
    else:
        level = logging.INFO

    init_console_logging(level=level)
    Database().connect()

    l = submit_tasks(
        target, options, package, custom, owner, timeout, priority, machine,
        platform, memory, enforce_timeout, clock, tags, remote, pattern, max,
        url, baseline, shuffle
    )

    for category, target, task_id in l:
        print "%s: %s \"%s\" added as task with ID #%s" % (
            bold(green("Success")), category, target, task_id
        )
