# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
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
    fetch_community, submit_tasks, process_tasks, process_task_range,
    cuckoo_rooter, cuckoo_api, cuckoo_distributed, cuckoo_distributed_instance,
    cuckoo_clean, cuckoo_dnsserve, cuckoo_machine, import_cuckoo,
    migrate_database
)
from cuckoo.common.config import read_kv_conf
from cuckoo.common.exceptions import CuckooCriticalError
from cuckoo.common.colors import yellow, red, green, bold
from cuckoo.common.logo import logo
from cuckoo.common.utils import exception_message
from cuckoo.core.database import Database
from cuckoo.core.init import write_supervisor_conf, write_cuckoo_conf
from cuckoo.core.resultserver import ResultServer
from cuckoo.core.scheduler import Scheduler
from cuckoo.core.startup import (
    check_configs, init_modules, check_version, init_logfile, init_logging,
    init_console_logging, init_tasks, init_yara, init_binaries, init_rooter,
    init_routing
)
from cuckoo.misc import (
    cwd, load_signatures, getuser, decide_cwd, drop_privileges
)

log = logging.getLogger("cuckoo")

def cuckoo_create(username=None, cfg=None):
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

    # The following effectively nops the first os.makedirs() call that
    # shutil.copytree() does as we've already created the destination directory
    # ourselves (assuming it didn't exist already).
    orig_makedirs = shutil.os.makedirs
    def _ignore_first_makedirs(dst):
        shutil.os.makedirs = orig_makedirs
    shutil.os.makedirs = _ignore_first_makedirs

    shutil.copytree(
        os.path.join(cuckoo.__path__[0], "data"),
        cwd(), symlinks=True, ignore=_ignore_pyc
    )

    # Drop our version of the CWD.
    our_version = open(cwd(".cwd", private=True), "rb").read()
    open(cwd(".cwd"), "wb").write(our_version)

    # Write the supervisord.conf configuration file.
    write_supervisor_conf(username or getuser())
    write_cuckoo_conf(cfg=cfg)

    print "Cuckoo has finished setting up the default configuration."
    print "Please modify the default settings where required and"
    print "start Cuckoo again (by running `cuckoo` or `cuckoo -d`)."

def cuckoo_init(level, ctx, cfg=None):
    """Initialize Cuckoo configuration.
    @param quiet: enable quiet mode.
    """
    logo()

    # It would appear this is the first time Cuckoo is being run (on this
    # Cuckoo Working Directory anyway).
    if not os.path.isdir(cwd()) or not os.listdir(cwd()):
        cuckoo_create(ctx.user, cfg)
        sys.exit(0)

    # Determine if this is a proper CWD.
    if not os.path.exists(cwd(".cwd")):
        sys.exit(
            "No proper Cuckoo Working Directory was identified, did you pass "
            "along the correct directory?"
        )

    # Determine if any CWD updates are required.
    current = open(cwd(".cwd"), "rb").read()
    latest = open(cwd(".cwd", private=True), "rb").read()
    if current != latest:
        pass

    check_configs()
    check_version()

    if ctx.log:
        init_logging(level)
    else:
        init_console_logging(level)

    Database().connect()

    # Load additional Signatures.
    load_signatures()

    init_modules()
    init_tasks()
    init_yara()
    init_binaries()
    init_rooter()
    init_routing()

def cuckoo_main(max_analysis_count=0):
    """Cuckoo main loop.
    @param max_analysis_count: kill cuckoo after this number of analyses
    """
    try:
        ResultServer()
        sched = Scheduler(max_analysis_count)
        sched.start()
    except KeyboardInterrupt:
        sched.stop()

@click.group(invoke_without_command=True)
@click.option("-d", "--debug", is_flag=True, help="Enable verbose logging")
@click.option("-q", "--quiet", is_flag=True, help="Only log warnings and critical messages")
@click.option("--nolog", is_flag=True, help="Don't log to file.")
@click.option("-m", "--maxcount", default=0, help="Maximum number of analyses to process")
@click.option("--user", help="Drop privileges to this user")
@click.option("--cwd", help="Cuckoo Working Directory")
@click.pass_context
def main(ctx, debug, quiet, nolog, maxcount, user, cwd):
    """Invokes the Cuckoo daemon or one of its subcommands.

    To be able to use different Cuckoo configurations on the same machine with
    the same Cuckoo installation, we use the so-called Cuckoo Working
    Directory (aka "CWD"). A default CWD is available, but may be overridden
    through the following options - listed in order of precedence.

    \b
    * Command-line option (--cwd)
    * Environment option ("CUCKOO_CWD")
    * Environment option ("CUCKOO")
    * Current directory (if the ".cwd" file exists)
    * Default value ("~/.cuckoo")
    """
    decide_cwd(cwd)

    # Drop privileges.
    user and drop_privileges(user)
    ctx.user = user

    ctx.log = not nolog

    if quiet:
        level = logging.WARN
    elif debug:
        level = logging.DEBUG
    else:
        level = logging.INFO

    ctx.level = level

    # A subcommand will be invoked, so don't run Cuckoo itself.
    if ctx.invoked_subcommand:
        return

    try:
        cuckoo_init(level, ctx)
        cuckoo_main(maxcount)
    except CuckooCriticalError as e:
        message = "{0}: {1}".format(e.__class__.__name__, e)
        if len(log.handlers):
            log.critical(message)
        else:
            sys.stderr.write("{0}\n".format(message))
        sys.exit(1)
    except SystemExit as e:
        if e.code:
            print e
    except:
        # Deal with an unhandled exception.
        message = exception_message()
        print message, traceback.format_exc()

@main.command()
@click.pass_context
@click.option("--conf", type=click.Path(exists=True, file_okay=True, readable=True), help="Flat key/value configuration file")
def init(ctx, conf):
    """Initializes a Cuckoo instance and checks its configuration/setup."""
    if conf and os.path.exists(conf):
        cfg = read_kv_conf(conf)
    else:
        cfg = None

    # If this is a new install, also apply the provided configuration.
    cuckoo_init(logging.INFO, ctx.parent, cfg)

    # If this is an existing install, overwrite the supervisord.conf
    # configuration file (if needed) as well as the Cuckoo configuration.
    write_supervisor_conf(ctx.parent.user or getuser())
    write_cuckoo_conf(cfg)

@main.command()
@click.option("-f", "--force", is_flag=True, help="Overwrite existing files")
@click.option("-b", "--branch", default="master", help="Specify a different community branch rather than master")
@click.option("--file", "--filepath", type=click.Path(exists=True), help="Specify a local copy of a community .tar.gz file")
def community(force, branch, filepath):
    """Utility to fetch supplies from the Cuckoo Community."""
    try:
        fetch_community(force=force, branch=branch, filepath=filepath)
    except KeyboardInterrupt:
        print(yellow("Aborting fetching of the Cuckoo Community resources.."))

@main.command()
def clean():
    """Utility to clean the Cuckoo Working Directory and associated
    databases."""
    try:
        cuckoo_clean()
    except KeyboardInterrupt:
        print(yellow("Aborting cleaning up of your CWD.."))

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
@click.pass_context
def submit(ctx, target, url, options, package, custom, owner, timeout,
           priority, machine, platform, memory, enforce_timeout, clock, tags,
           baseline, remote, shuffle, pattern, max, unique):
    """Submit one or more files or URLs to Cuckoo."""
    init_console_logging(level=ctx.parent.level)
    Database().connect()

    try:
        l = submit_tasks(
            target, options, package, custom, owner, timeout, priority,
            machine, platform, memory, enforce_timeout, clock, tags, remote,
            pattern, max, unique, url, baseline, shuffle
        )

        for category, target, task_id in l:
            if task_id:
                print "%s: %s \"%s\" added as task with ID #%s" % (
                    bold(green("Success")), category, target, task_id
                )
            else:
                print "%s: %s \"%s\" as it has already been analyzed" % (
                    bold(yellow("Skipped")), category, target
                )
    except KeyboardInterrupt:
        print(red("Aborting submission of samples.."))

@main.command()
@click.argument("instance", required=False)
@click.option("-r", "--report", help="Re-generate one or more reports")
@click.option("-m", "--maxcount", default=0, help="Maximum number of analyses to process")
@click.pass_context
def process(ctx, instance, report, maxcount):
    """Process raw task data into reports."""
    init_console_logging(level=ctx.parent.level)

    if instance:
        init_logfile("process-%s.json" % instance)

    Database().connect()

    # Load additional Signatures.
    load_signatures()

    # Initialize all modules.
    init_modules()

    try:
        # Regenerate one or more reports.
        if report:
            process_task_range(report)
        elif not instance:
            print ctx.get_help(), "\n"
            sys.exit("In automated mode an instance name is required!")
        else:
            log.info(
                "Initialized instance=%s, ready to process some tasks",
                instance
            )
            process_tasks(instance, maxcount)
    except KeyboardInterrupt:
        print(red("Aborting (re-)processing of your analyses.."))

@main.command()
@click.argument("socket", type=click.Path(readable=False, dir_okay=False), default="/tmp/cuckoo-rooter", required=False)
@click.option("-g", "--group", default="cuckoo", help="Unix socket group")
@click.option("--ifconfig", type=click.Path(exists=True), default="/sbin/ifconfig", help="Path to ifconfig(8)")
@click.option("--service", type=click.Path(exists=True), default="/usr/sbin/service", help="Path to service(8) for invoking OpenVPN")
@click.option("--iptables", type=click.Path(exists=True), default="/sbin/iptables", help="Path to iptables(8)")
@click.option("--ip", type=click.Path(exists=True), default="/sbin/ip", help="Path to ip(8)")
@click.option("--sudo", is_flag=True)
@click.pass_context
def rooter(ctx, socket, group, ifconfig, service, iptables, ip, sudo):
    init_console_logging(level=ctx.parent.level)

    if sudo:
        args = [
            "sudo", sys.argv[0], "rooter", socket,
            "--group", group,
            "--ifconfig", ifconfig,
            "--service", service,
            "--iptables", iptables,
            "--ip", ip,
        ]

        if ctx.parent.level == logging.DEBUG:
            args.insert(2, "--debug")

        try:
            subprocess.call(args)
        except KeyboardInterrupt:
            pass
    else:
        try:
            cuckoo_rooter(socket, group, ifconfig, service, iptables, ip)
        except KeyboardInterrupt:
            print(red("Aborting the Cuckoo Rooter.."))

@main.command()
@click.option("-H", "--host", default="localhost", help="Host to bind the API server on")
@click.option("-p", "--port", default=8090, help="Port to bind the API server on")
@click.option("--uwsgi", is_flag=True, help="Dump uWSGI configuration")
@click.option("--nginx", is_flag=True, help="Dump nginx configuration")
@click.pass_context
def api(ctx, host, port, uwsgi, nginx):
    username = ctx.parent.user or getuser()
    if uwsgi:
        print "[uwsgi]"
        print "plugins = python"
        if os.environ.get("VIRTUAL_ENV"):
            print "virtualenv =", os.environ["VIRTUAL_ENV"]
        print "module = cuckoo.apps.api"
        print "callable = app"
        print "uid =", username
        print "gid =", username
        print "env = CUCKOO_APP=api"
        print "env = CUCKOO_CWD=%s" % cwd()
        return

    if nginx:
        print "upstream _uwsgi_cuckoo_api {"
        print "    server unix:/run/uwsgi/app/cuckoo-api/socket;"
        print "}"
        print
        print "server {"
        print "    listen %s:%d;" % (host, port)
        print
        print "    # REST API app"
        print "    location / {"
        print "        client_max_body_size 1G;"
        print "        uwsgi_pass  _uwsgi_cuckoo_api;"
        print "        include     uwsgi_params;"
        print "    }"
        print "}"
        return

    init_console_logging(level=ctx.parent.level)
    Database().connect()
    cuckoo_api(host, port, ctx.parent.level == logging.DEBUG)

@main.command()
@click.option("-H", "--host", default="0.0.0.0", help="IP address to bind for the DNS server")
@click.option("-p", "--port", default=53, help="UDP port to bind to for the DNS server")
@click.option("--nxdomain", help="IP address to return instead of NXDOMAIN")
@click.option("--hardcode", help="Hardcoded IP address to return instead of actually doing DNS lookups")
@click.pass_context
def dnsserve(ctx, host, port, nxdomain, hardcode):
    init_console_logging(ctx.parent.level)
    try:
        cuckoo_dnsserve(host, port, nxdomain, hardcode)
    except KeyboardInterrupt:
        print(red("Aborting Cuckoo DNS Serve.."))

@main.command()
@click.argument("args", nargs=-1)
@click.option("-H", "--host", default="localhost", help="Host to bind the Web Interface server on")
@click.option("-p", "--port", default=8000, help="Port to bind the Web Interface server on")
@click.option("--uwsgi", is_flag=True, help="Dump uWSGI configuration")
@click.option("--nginx", is_flag=True, help="Dump nginx configuration")
@click.pass_context
def web(ctx, args, host, port, uwsgi, nginx):
    """Starts the Cuckoo Web Interface or dumps its uwsgi/nginx configuration.

    Use "--help" to get this help message and "help" to find Django's
    manage.py potential subcommands.
    """
    username = ctx.parent.user or getuser()
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
        print "env = CUCKOO_APP=web"
        print "env = CUCKOO_CWD=%s" % cwd()
        return

    if nginx:
        print "upstream _uwsgi_cuckoo_web {"
        print "    server unix:/run/uwsgi/app/cuckoo-web/socket;"
        print "}"
        print
        print "server {"
        print "    listen %s:%d;" % (host, port)
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

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cuckoo.web.web.settings")

    # The Django HTTP server also imports the WSGI module for some reason, so
    # ensure that WSGI is able to load.
    os.environ["CUCKOO_APP"] = "web"
    os.environ["CUCKOO_CWD"] = cwd()

    from django.core.management import execute_from_command_line

    init_console_logging(level=ctx.parent.level)
    Database().connect()

    if not args:
        execute_from_command_line(
            ("cuckoo", "runserver", "%s:%d" % (host, port))
        )
    else:
        execute_from_command_line(("cuckoo",) + args)

@main.command()
@click.argument("vmname")
@click.argument("ip", default="")
@click.option("--add", "action", flag_value="add", help="Add a Virtual Machine")
@click.option("--delete", "action", flag_value="delete", help="Delete a Virtual Machine")
@click.option("--platform", default="windows", help="Guest Operating System")
@click.option("--options", help="Machine options")
@click.option("--tags", help="Tags for this Virtual Machine")
@click.option("--interface", help="Sniffer interface for this Virtual Machine")
@click.option("--snapshot", help="Specific Virtual Machine Snapshot to use")
@click.option("--resultserver", help="IP:Port of the Result Server")
@click.pass_context
def machine(ctx, vmname, ip, action, platform, options, tags, interface,
            snapshot, resultserver):
    init_console_logging(level=ctx.parent.level)
    Database().connect()
    cuckoo_machine(
        vmname, action, ip, platform, options, tags, interface,
        snapshot, resultserver
    )

@main.command()
@click.option("--revision", default="head", help="Migrate to a certain revision")
def migrate(revision):
    if not migrate_database(revision):
        print red(">>> Error migrating your database..")
        exit(1)

    print yellow(">>> Your database migration was successful!")

@main.command("import")
@click.argument("path", type=click.Path(file_okay=False, exists=True))
@click.option("-f", "--force", is_flag=True, help="Perform non-reversible in-place database migrations")
@click.option("--database", help="Creation of a new database for a reversible migration")
@click.option("-r", "--reference", "mode", flag_value="reference", default=True)
@click.option("-c", "--copy", "mode", flag_value="copy")
@click.pass_context
def import_(ctx, path, force, database, mode):
    if force and database:
        sys.exit("Can't have both the --force and the --database parameter.")

    try:
        # TODO Actually symlink or copy analyses.
        import_cuckoo(ctx.parent.user, path, force, database)
    except KeyboardInterrupt:
        print(red("Aborting import of Cuckoo instance.."))

@main.group()
def distributed():
    pass

@distributed.command()
@click.option("-H", "--host", default="localhost", help="Host to bind the Distributed Cuckoo server on")
@click.option("-p", "--port", default=9003, help="Port to bind the Distributed Cuckoo server on")
@click.option("--uwsgi", is_flag=True, help="Dump uWSGI configuration")
@click.option("--nginx", is_flag=True, help="Dump nginx configuration")
@click.pass_context
def server(ctx, host, port, uwsgi, nginx):
    username = ctx.parent.parent.user or getuser()
    if uwsgi:
        print "[uwsgi]"
        print "plugins = python"
        if os.environ.get("VIRTUAL_ENV"):
            print "virtualenv =", os.environ["VIRTUAL_ENV"]
        print "module = cuckoo.apps.distributed"
        print "callable = app"
        print "uid =", username
        print "gid =", username
        print "env = CUCKOO_APP=dist"
        print "env = CUCKOO_CWD=%s" % cwd()
        return

    if nginx:
        print "upstream _uwsgi_cuckoo_distributed {"
        print "    server unix:/run/uwsgi/app/cuckoo-distributed/socket;"
        print "}"
        print
        print "server {"
        print "    listen %s:%d;" % (host, port)
        print
        print "    # REST Distributed app"
        print "    location / {"
        print "        client_max_body_size 1G;"
        print "        uwsgi_pass  _uwsgi_cuckoo_distributed;"
        print "        include     uwsgi_params;"
        print "    }"
        print "}"
        return

    cuckoo_distributed(host, port, ctx.parent.parent.level == logging.DEBUG)

@distributed.command("instance")
@click.argument("name")
@click.pass_context
def dist_instance(ctx, name):
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    init_console_logging(ctx.parent.parent.level)
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
