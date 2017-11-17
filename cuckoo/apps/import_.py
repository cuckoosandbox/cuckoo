# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import click
import os.path
import logging
import shutil
import subprocess
import sqlalchemy

from cuckoo.common.config import Config
from cuckoo.common.colors import yellow, red
from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.compat.config import migrate as migrate_conf
from cuckoo.misc import cwd, is_windows

log = logging.getLogger(__name__)

def identify(dirpath):
    filepath = os.path.join(dirpath, "lib", "cuckoo", "common", "constants.py")
    if os.path.exists(filepath):
        for line in open(filepath, "rb"):
            if line.startswith("CUCKOO_VERSION"):
                return line.split('"')[1]

def _dburi_engine(dburi):
    # Defaults to a sqlite3 database.
    if not dburi:
        dburi = "sqlite:///db/cuckoo.db"

    try:
        return sqlalchemy.create_engine(dburi).engine
    except sqlalchemy.exc.ArgumentError:
        raise CuckooOperationalError(
            "Error creating SQL database backup as your SQL database URI "
            "wasn't understood by us: %r!" % dburi
        )

def dumpcmd(dburi, dirpath):
    engine = _dburi_engine(dburi)

    if engine.name == "sqlite":
        # If the SQLite3 database filepath is relative, then make it relative
        # against the old Cuckoo setup. If it's absolute, os.path.join() will
        # keep it absolute as-is (see also our version 1.1.1 release :-P).
        return [
            "sqlite3", os.path.join(dirpath, engine.url.database), ".dump"
        ], {}

    if engine.name == "mysql":
        args = ["mysqldump"]
        if engine.url.username:
            args += ["-u", engine.url.username]
        if engine.url.password:
            args.append("-p%s" % engine.url.password)
        if engine.url.host and engine.url.host != "localhost":
            args += ["-h", engine.url.host]
        args.append(engine.url.database)
        return args, {}

    if engine.name == "postgresql":
        args, env = ["pg_dump"], {}
        if engine.url.username:
            args += ["-U", engine.url.username]
        if engine.url.password:
            env["PGPASSWORD"] = engine.url.password
        if engine.url.host and engine.url.host != "localhost":
            args += ["-h", engine.url.host]
        args.append(engine.url.database)
        return args, env

    raise CuckooOperationalError(
        "Error creating SQL database backup as your SQL database URI "
        "wasn't understood by us: %r!" % dburi
    )

def movesql(dburi, mode, dirpath):
    engine = _dburi_engine(dburi)
    if engine.name != "sqlite":
        return

    if mode == "copy":
        import_file = shutil.copy
    elif mode == "move":
        import_file = shutil.move
    elif mode == "symlink":
        if is_windows():
            raise RuntimeError("Can't use 'symlink' mode under Windows!")
        import_file = os.symlink

    # For more information on the os.path.join() usage see also dumpcmd().
    import_file(
        os.path.abspath(os.path.join(dirpath, engine.url.database)),
        cwd("cuckoo.db")
    )

def sqldump(dburi, dirpath):
    args, env = dumpcmd(dburi, dirpath)

    envargs = " ".join("%s=%s" % (k, v) for k, v in env.items())
    cmdline = " ".join('"%s"' % arg if " " in arg else arg for arg in args)
    cmd = "%s %s" % (envargs, cmdline) if envargs else cmdline

    print "We can make a SQL database backup as follows:"
    print "input cmd  =>", cmd
    print "output SQL =>", cwd("backup.sql")

    if not click.confirm("Would you like to make a backup", default=True):
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

    dburi = cfg["cuckoo"]["database"]["connection"]

    # Ask if the user would like to make a backup of the SQL database and in
    # the case of sqlite3, copy/move/symlink cuckoo.db to the CWD.
    sqldump(dburi, dirpath)
    movesql(dburi, mode, dirpath)

    # Run database migrations.
    if not migrate_database():
        raise CuckooOperationalError(
            "Error migrating your old Cuckoo database!"
        )

    # Link or copy all of the older results to the new CWD.
    import_legacy_analyses(mode, dirpath)

    # Urge the user to run the community command.
    print
    print "You have successfully imported your old version of Cuckoo!"
    print "However, in order to get up-to-date, you'll probably want to"
    print yellow("run the community command"),
    print "by running", red("'cuckoo community'"), "manually."
    print "The community command will fetch the latest monitoring updates"
    print "and Cuckoo Signatures."

def import_analysis_copy(src, dst):
    def ignore(src, names):
        if "binary" not in names:
            return []
        if not os.path.exists(os.path.join(src, "binary")):
            return ["binary"]
        return []

    shutil.copytree(src, dst, ignore=ignore)

def import_legacy_analyses(mode, dirpath):
    """Imports the raw results of a legacy analysis. Using either the 'copy',
    'move', or 'symlink' mode."""
    if mode == "copy":
        import_analysis = import_analysis_copy
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
