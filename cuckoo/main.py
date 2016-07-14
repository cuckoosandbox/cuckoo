# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import click
import logging
import os
import shutil
import subprocess
import sys
import traceback

import cuckoo

from cuckoo.apps import (
    fetch_community, submit_tasks, process_tasks, process_task, cuckoo_rooter,
    cuckoo_api, cuckoo_distributed, cuckoo_distributed_instance,
    cuckoo_dnsserve, cuckoo_machine
)
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
from cuckoo.misc import cwd, set_cwd, load_signatures

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

    def _ignore_pyc(src, names):
        """Don't copy .pyc files."""
        return [name for name in names if name.endswith(".pyc")]

    dirpath = os.path.join(cuckoo.__path__[0], "data")
    for filename in os.listdir(dirpath):
        filepath = os.path.join(dirpath, filename)
        if os.path.isfile(filepath):
            if not filepath.endswith(".pyc"):
                shutil.copy(filepath, cwd(filename))
        else:
            shutil.copytree(
                filepath, cwd(filename), symlinks=True, ignore=_ignore_pyc
            )

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
@click.option("-d", "--debug", is_flag=True, help="Enable verbose logging")
@click.option("-q", "--quiet", is_flag=True, help="Only log warnings and critical messages")
@click.option("-m", "--maxcount", default=0, help="Maximum number of analyses to process")
@click.option("--user", help="Drop privileges to this user")
@click.option("--cwd", envvar="CUCKOO", default="~/.cuckoo", help="Cuckoo Working Directory")
@click.pass_context
def main(ctx, debug, quiet, maxcount, user, cwd):
    # Cuckoo Working Directory precedence:
    # * Command-line option (--cwd)
    # * Environment option ("CUCKOO")
    # * Default value ("~/.cuckoo")
    set_cwd(os.path.abspath(os.path.expanduser(cwd)), raw=cwd)

    # Drop privileges.
    user and drop_privileges(user)
    ctx.user = user

    # Load additional Signatures.
    load_signatures()

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
    Database().connect()
    cuckoo_clean()

@main.command()
@click.argument("target", nargs=-1)
@click.option("-u", "--url", is_flag=True, help="Submitting URLs instead of samples")
@click.option("-o", "--options", help="Options for these tasks")
@click.option("--package", help="Analysis package to use")
@click.option("--custom", help="Custom information to pass along this task")
@click.option("--owner", help="Owner of this task")
@click.option("--timeout", type=int, help="Analysis time in seconds")
@click.option("--priority", type=int, help="Priority of this task")
@click.option("--machine", help="Machine to analyze these tasks on")
@click.option("--platform", help="Analysis platform")
@click.option("--memory", is_flag=True, help="Enable memory dumping")
@click.option("--enforce-timeout", is_flag=True, help="Don't terminate the analysis early")
@click.option("--clock", help="Set the system clock")
@click.option("--tags", help="Analysis tags")
@click.option("--baseline", is_flag=True, help="Create baseline task")
@click.option("--remote", help="Submit to a remote Cuckoo instance")
@click.option("--shuffle", is_flag=True, help="Shuffle the submitted tasks")
@click.option("--pattern", help="Provide a glob-pattern when submitting a directory")
@click.option("--max", type=int, help="Submit up to X tasks at once")
@click.option("--unique", is_flag=True, help="Only submit samples that have not been analyzed before")
@click.option("-d", "--debug", is_flag=True, help="Enable verbose logging")
@click.option("-q", "--quiet", is_flag=True, help="Only log warnings and critical messages")
def submit(target, url, options, package, custom, owner, timeout, priority,
           machine, platform, memory, enforce_timeout, clock, tags, baseline,
           remote, shuffle, pattern, max, unique, debug, quiet):
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
        unique, url, baseline, shuffle
    )

    for category, target, task_id in l:
        if task_id:
            print "%s: %s \"%s\" added as task with ID #%s" % (
                bold(green("Success")), category, target, task_id
            )
        else:
            print "%s: %s \"%s\" skipped as it has already been analyzed" % (
                bold(green("Success")), category, target, task_id
            )

@main.command()
@click.argument("instance", required=False)
@click.option("-r", "--report", default=0, help="Re-generate a report")
@click.option("-m", "--maxcount", default=0, help="Maximum number of analyses to process")
@click.option("-d", "--debug", is_flag=True, help="Enable verbose logging")
@click.option("-q", "--quiet", is_flag=True, help="Only log warnings and critical messages")
@click.pass_context
def process(ctx, instance, report, maxcount, debug, quiet):
    """Process raw task data into reports."""
    if quiet:
        level = logging.WARN
    elif debug:
        level = logging.DEBUG
    else:
        level = logging.INFO

    init_console_logging(level=level)

    db = Database()
    db.connect()

    # Regenerate a report.
    if report:
        task = db.view_task(report)
        if not task:
            task = {
                "id": report,
                "category": "file",
                "target": "",
                "options": "",
            }
        else:
            task = task.to_dict()

        process_task(task, db)
    elif not instance:
        print ctx.get_help(), "\n"
        sys.exit("In automated mode an instance name is required!")
    else:
        log.info("Initialized instance=%s, ready to process some tasks", instance)
        process_tasks(instance, maxcount)

@main.command()
@click.argument("socket", default="/tmp/cuckoo-rooter", required=False)
@click.option("-g", "--group", default="cuckoo", help="Unix socket group")
@click.option("--ifconfig", default="/sbin/ifconfig", help="Path to ifconfig(8)")
@click.option("--service", default="/usr/sbin/service", help="Path to service(8) for invoking OpenVPN")
@click.option("--iptables", default="/sbin/iptables", help="Path to iptables(8)")
@click.option("--ip", default="/sbin/ip", help="Path to ip(8)")
@click.option("-v", "--verbose", is_flag=True)
def rooter(socket, group, ifconfig, service, iptables, ip, verbose):
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    cuckoo_rooter(socket, group, ifconfig, service, iptables, ip)

@main.command()
@click.option("-H", "--host", default="localhost", help="Host to bind the API server on")
@click.option("-p", "--port", default=8090, help="Port to bind the API server on")
@click.option("-d", "--debug", is_flag=True, help="Start the API in debug mode")
@click.option("--uwsgi", is_flag=True, help="Dump uWSGI configuration")
@click.option("--nginx", is_flag=True, help="Dump nginx configuration")
@click.pass_context
def api(ctx, host, port, debug, uwsgi, nginx):
    username = ctx.parent.user or os.getlogin()
    if uwsgi:
        print "[uwsgi]"
        print "plugins = python"
        if os.environ.get("VIRTUAL_ENV"):
            print "virtualenv =", os.environ["VIRTUAL_ENV"]
        print "module = cuckoo.apps.api"
        print "callable = app"
        print "uid =", username
        print "gid =", username
        print "env = CUCKOO_FORCE=%s" % cwd()
        print "env = CUCKOO_APP=api"
        return

    if nginx:
        print "upstream _uwsgi_cuckoo_api {"
        print "    server unix:/run/uwsgi/app/cuckoo-api/socket;"
        print "}"
        print
        print "server {"
        print "    listen %d;" % port
        print "    listen [::]:%d ipv6only=on;" % port
        print
        print "    # REST API app"
        print "    location / {"
        print "        client_max_body_size 1G;"
        print "        uwsgi_pass  _uwsgi_cuckoo_api;"
        print "        include     uwsgi_params;"
        print "    }"
        print "}"
        return

    Database().connect()

    cuckoo_api(host, port, debug)

@main.command()
@click.option("-H", "--host", default="0.0.0.0", help="IP address to bind for the DNS server")
@click.option("-p", "--port", default=53, help="UDP port to bind to for the DNS server")
@click.option("--nxdomain", help="IP address to return instead of NXDOMAIN")
@click.option("--hardcode", help="Hardcoded IP address to return instead of actually doing DNS lookups")
@click.option("-v", "--verbose", is_flag=True)
def dnsserve(host, port, nxdomain, hardcode, verbose):
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    cuckoo_dnsserve(host, port, nxdomain, hardcode)

@main.command()
@click.argument("args", nargs=-1)
@click.option("-p", "--port", default=8000, help="Port to bind the API server on")
@click.option("--uwsgi", is_flag=True, help="Dump uWSGI configuration")
@click.option("--nginx", is_flag=True, help="Dump nginx configuration")
@click.pass_context
def web(ctx, args, port, uwsgi, nginx):
    username = ctx.parent.user or os.getlogin()
    if uwsgi:
        print "[uwsgi]"
        print "plugins = python"
        if os.environ.get("VIRTUAL_ENV"):
            print "virtualenv =", os.environ["VIRTUAL_ENV"]
        print "module = cuckoo.web.web.wsgi"
        print "uid =", username
        print "gid =", username
        dirpath = os.path.join(cuckoo.__path__[0], "web", "static")
        print "static-map = /static=%s" % dirpath
        print "# If you're getting errors about the PYTHON_EGG_CACHE, then"
        print "# uncomment the following line and add some path that is"
        print "# writable from the defined user."
        print "# env = PYTHON_EGG_CACHE="
        print "env = CUCKOO_FORCE=%s" % cwd()
        print "env = CUCKOO_APP=web"
        return

    if nginx:
        print "upstream _uwsgi_cuckoo_web {"
        print "    server unix:/run/uwsgi/app/cuckoo-web/socket;"
        print "}"
        print
        print "server {"
        print "    listen %d;" % port
        print "    listen [::]:%d ipv6only=on;" % port
        print
        print "    # Cuckoo Web Interface"
        print "    location / {"
        print "        client_max_body_size 1G;"
        print "        uwsgi_pass  _uwsgi_cuckoo_web;"
        print "        include     uwsgi_params;"
        print "    }"
        print "}"
        return

    # Switch to cuckoo/web and add the current path to sys.path as the Web
    # Interface is using local imports here and there.
    # TODO Rename local imports to either cuckoo.web.* or relative imports.
    os.chdir(os.path.join(cuckoo.__path__[0], "web"))
    sys.path.insert(0, ".")

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "web.settings")

    from django.core.management import execute_from_command_line

    Database().connect()
    execute_from_command_line(("cuckoo",) + args)

@main.command()
@click.argument("vmname")
@click.argument("ip", default="")
@click.option("--debug", is_flag=True, help="Enable verbose logging")
@click.option("--add", is_flag=True, help="Add a Virtual Machine")
@click.option("--delete", is_flag=True, help="Delete a Virtual Machine")
@click.option("--platform", default="windows", help="Guest Operating System")
@click.option("--options", help="Machine options")
@click.option("--tags", help="Tags for this Virtual Machine")
@click.option("--interface", help="Sniffer interface for this Virtual Machine")
@click.option("--snapshot", help="Specific Virtual Machine Snapshot to use")
@click.option("--resultserver", help="IP:Port of the Result Server")
def machine(debug, vmname, ip, add, delete, platform, options, tags,
            interface, snapshot, resultserver):
    if debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if add and not ip:
        sys.exit("You have to specify a legitimate IP address for --add.")

    Database().connect()
    cuckoo_machine(vmname, add, delete, ip, platform, options, tags,
                   interface, snapshot, resultserver)

@main.command()
def migrate():
    args = [
        "alembic", "-x", "cwd=%s" % cwd(), "upgrade", "head",
    ]
    try:
        subprocess.check_call(args, cwd=cwd("db_migration", private=True))
    except subprocess.CalledProcessError:
        print red(">>> Error migrating your database..")
        exit(1)

    print yellow(">>> Your database migration was successful!")

@main.group()
def distributed():
    pass

@distributed.command()
@click.option("-H", "--host", default="0.0.0.0", help="Host to bind the Distributed Cuckoo server on")
@click.option("-p", "--port", default=9003, help="Port to bind the Distributed Cuckoo server on")
@click.option("-d", "--debug", is_flag=True, help="Start the Distributed Cuckoo server in debug mode")
@click.option("--uwsgi", is_flag=True, help="Dump uWSGI configuration")
@click.option("--nginx", is_flag=True, help="Dump nginx configuration")
@click.pass_context
def server(ctx, host, port, debug, uwsgi, nginx):
    username = ctx.parent.parent.user or os.getlogin()
    if uwsgi:
        print "[uwsgi]"
        print "plugins = python"
        if os.environ.get("VIRTUAL_ENV"):
            print "virtualenv =", os.environ["VIRTUAL_ENV"]
        print "module = cuckoo.apps.distributed"
        print "callable = app"
        print "uid =", username
        print "gid =", username
        print "env = CUCKOO_FORCE=%s" % cwd()
        print "env = CUCKOO_APP=dist"
        return

    if nginx:
        print "upstream _uwsgi_cuckoo_distributed {"
        print "    server unix:/run/uwsgi/app/cuckoo-distributed/socket;"
        print "}"
        print
        print "server {"
        print "    listen %d;" % port
        print "    listen [::]:%d ipv6only=on;" % port
        print
        print "    # REST Distributed app"
        print "    location / {"
        print "        client_max_body_size 1G;"
        print "        uwsgi_pass  _uwsgi_cuckoo_distributed;"
        print "        include     uwsgi_params;"
        print "    }"
        print "}"
        return

    if debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    cuckoo_distributed(host, port, debug)

@distributed.command("instance")
@click.argument("name")
@click.option("-d", "--debug", is_flag=True, help="Start the Distributed Cuckoo server in debug mode")
def dist_instance(name, debug):
    if debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    cuckoo_distributed_instance(name)

@distributed.command("migrate")
def dist_migrate():
    args = [
        "alembic", "-x", "cwd=%s" % cwd(), "upgrade", "head",
    ]
    try:
        subprocess.check_call(
            args, cwd=cwd("distributed", "migration", private=True)
        )
    except subprocess.CalledProcessError:
        print red(">>> Error migrating your database..")
        exit(1)

    print yellow(">>> Your database migration was successful!")
