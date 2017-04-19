# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import click
import os.path
import logging
import re
import shutil
import subprocess

from cuckoo.common.config import Config
from cuckoo.common.colors import yellow
from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.compat.config import migrate as migrate_conf
from cuckoo.misc import cwd, is_windows

log = logging.getLogger(__name__)

SQLRE = "(\\w+)://(?:(\\w*):?([^@]*)@)?([\\w.-]+)/([\\w-]+)"

def identify(dirpath):
    filepath = os.path.join(dirpath, "lib", "cuckoo", "common", "constants.py")
    if os.path.exists(filepath):
        for line in open(filepath, "rb"):
            if line.startswith("CUCKOO_VERSION"):
                return line.split('"')[1]

def dumpcmd(dburi, dirpath):
    if not dburi:
        # Defaults to a SQLite3 database.
        return [
            "sqlite3", os.path.join(dirpath, "db", "cuckoo.db"), ".dump"
        ], {}

    if dburi.startswith("sqlite:///"):
        # If the SQLite3 database filepath is relative, then make it relative
        # against the old Cuckoo setup. If it's absolute, os.path.join() will
        # keep it absolute as-is (see also our version 1.1.1 release :-P).
        filepath = dburi.split(":///", 1)[1]
        return [
            "sqlite3", os.path.join(dirpath, filepath), ".dump"
        ], {}

    env = {}
    l = re.match(SQLRE, dburi).groups()
    engine, username, password, hostname, database = l

    if engine == "mysql":
        args = ["mysqldump"]
        if username:
            args += ["-u", username]
        if password:
            args.append("-p%s" % password)
        if hostname and hostname != "localhost":
            args += ["-h", hostname]
        args.append(database)
        return args, {}

    if engine == "postgresql":
        args = ["pg_dump"]
        if username:
            args += ["-U", username]
        if password:
            env["PGPASSWORD"] = password
        if hostname and hostname != "localhost":
            args += ["-h", hostname]
        args.append(database)
        return args, env

    return None, None

def sqldump(dburi, dirpath):
    args, env = dumpcmd(dburi, dirpath)
    if not args:
        raise CuckooOperationalError(
            "Error creating SQL database backup as your SQL database "
            "configuration wasn't understood by us (database URI=%s)!" % dburi
        )

    envargs = " ".join("%s=%s" % (k, v) for k, v in env.items())
    cmdline = " ".join('"%s"' % arg if " " in arg else arg for arg in args)
    cmd = "%s %s" % (envargs, cmdline) if envargs else cmdline

    print "We can make a SQL database backup as follows:"
    print "input cmd  =>", cmd
    print "output SQL =>", cwd("backup.sql")

    if not click.confirm("Would you like to make a backup"):
        return

    try:
        subprocess.check_call(
            args, stdout=open(cwd("backup.sql"), "wb"),
            env=dict(os.environ.items() + env.items())
        )
    except (subprocess.CalledProcessError, OSError) as e:
        raise CuckooOperationalError(
            "Error creating SQL database dump as the command returned an "
            "error code: %s. Please make sure that the required tooling "
            "for making a database backup is installed and review the "
            "database URI to make sure it's correct: %s!" % (e, dburi)
        )

def import_cuckoo(username, mode, dirpath):
    version = identify(dirpath)
    if not version:
        raise CuckooOperationalError(
            "The path that you specified is not a proper Cuckoo setup. Please "
            "point the path to the root of your older Cuckoo setup, i.e., to "
            "the directory containing the cuckoo.py script!"
        )

    # TODO Copy over the configuration and ignore the database.
    if version in ("0.4", "0.4.1", "0.4.2"):
        raise CuckooOperationalError(
            "Importing from version 0.4, 0.4.1, or 0.4.2 is not supported as "
            "there are no database migrations for that version. Please start "
            "from scratch, your configuration would have been obsolete anyway!"
        )

    print "We've identified a Cuckoo Sandbox %s installation!" % version

    if os.path.isdir(cwd()) and os.listdir(cwd()):
        raise CuckooOperationalError(
            "This Cuckoo Working Directory already exists. Please import to "
            "a new/clean Cuckoo Working Directory."
        )

    # Following are various recursive imports.
    from cuckoo.apps import migrate_database
    from cuckoo.main import cuckoo_create

    print "Reading in the old configuration.."

    # Port the older configuration.
    cfg = Config.from_confdir(os.path.join(dirpath, "conf"), loose=True)
    cfg = migrate_conf(cfg, version)

    print "  configuration has been migrated to the latest version!"
    print

    # Create a fresh Cuckoo Working Directory.
    cuckoo_create(username, cfg, quiet=True)

    # Ask if the user would like to make a backup of the SQL database.
    sqldump(cfg["cuckoo"]["database"]["connection"], dirpath)

    # Run database migrations.
    if not migrate_database():
        raise CuckooOperationalError(
            "Error migrating your old Cuckoo database!"
        )

    # Link or copy all of the older results to the new CWD.
    import_legacy_analyses(mode, dirpath)

    # Urge the user to run the community command.
    print "You have successfully imported your old version of Cuckoo!"
    print "However, in order to get up-to-date, you'll probably want to"
    print " "*10, yellow("run the community command")
    print "by running 'cuckoo community' manually."
    print "The community command will fetch the latest monitoring updates"
    print "and Cuckoo Signatures."

def import_legacy_analyses(mode, dirpath):
    """Imports the raw results of a legacy analysis. Using either the 'copy',
    'move', or 'symlink' mode."""
    if mode == "copy":
        import_analysis = shutil.copytree
    elif mode == "move":
        import_analysis = shutil.move
    elif mode == "symlink":
        if is_windows():
            raise RuntimeError("Can't use 'symlink' mode under Windows!")
        import_analysis = os.symlink

    analyses = os.path.join(dirpath, "storage", "analyses")
    if not os.path.isdir(analyses):
        log.warning("Didn't find any analyses, so not much to import!")
        return

    tasks = []
    for task_id in os.listdir(analyses):
        if task_id == "latest":
            continue

        import_analysis(
            os.path.join(analyses, task_id), cwd(analysis=task_id)
        )
        tasks.append(int(task_id))
    return tasks
