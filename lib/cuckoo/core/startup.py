# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil
import sys
import copy
import json
import urllib
import urllib2
import logging
import logging.handlers
import pwd
import time

from datetime import datetime, timedelta

from lib.cuckoo.common.colors import red, green, yellow, cyan
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_VERSION
from lib.cuckoo.common.exceptions import CuckooStartupError, CuckooDatabaseError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.utils import create_folders
from lib.cuckoo.core.database import Database, TASK_RUNNING, TASK_FAILED_ANALYSIS
from lib.cuckoo.core.plugins import import_plugin, import_package, list_plugins

try:
    import pefile
    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False

log = logging.getLogger()

def check_python_version():
    """Checks if Python version is supported by Cuckoo.
    @raise CuckooStartupError: if version is not supported.
    """
    if sys.version_info[:2] != (2, 7):
        raise CuckooStartupError("You are running an incompatible version "
                                 "of Python, please use 2.7")


def check_working_directory():
    """Checks if working directories are ready.
    @raise CuckooStartupError: if directories are not properly configured.
    """
    if not os.path.exists(CUCKOO_ROOT):
        raise CuckooStartupError("You specified a non-existing root "
                                 "directory: {0}".format(CUCKOO_ROOT))

    cwd = os.path.join(os.getcwd(), "cuckoo.py")
    if not os.path.exists(cwd):
        raise CuckooStartupError("You are not running Cuckoo from it's "
                                 "root directory")


def check_configs():
    """Checks if config files exist.
    @raise CuckooStartupError: if config files do not exist.
    """
    configs = [
        os.path.join(CUCKOO_ROOT, "conf", "auxiliary.conf"),
        os.path.join(CUCKOO_ROOT, "conf", "cuckoo.conf"),
        os.path.join(CUCKOO_ROOT, "conf", "esx.conf"),
        os.path.join(CUCKOO_ROOT, "conf", "kvm.conf"),
        os.path.join(CUCKOO_ROOT, "conf", "memory.conf"),
        os.path.join(CUCKOO_ROOT, "conf", "physical.conf"),
        os.path.join(CUCKOO_ROOT, "conf", "processing.conf"),
        os.path.join(CUCKOO_ROOT, "conf", "qemu.conf"),
        os.path.join(CUCKOO_ROOT, "conf", "reporting.conf"),
        os.path.join(CUCKOO_ROOT, "conf", "virtualbox.conf"),
        os.path.join(CUCKOO_ROOT, "conf", "vmware.conf"),
        os.path.join(CUCKOO_ROOT, "conf", "xenserver.conf"),
    ]

    for config in configs:
        if not os.path.exists(config):
            raise CuckooStartupError("Config file does not exist at "
                                     "path: {0}".format(config))

    return True

def create_structure():
    """Creates Cuckoo directories."""
    folders = [
        "log",
        "storage",
        os.path.join("storage", "analyses"),
        os.path.join("storage", "binaries")
    ]

    try:
        create_folders(root=CUCKOO_ROOT, folders=folders)
    except CuckooOperationalError as e:
        raise CuckooStartupError(e)

def check_version():
    """Checks version of Cuckoo."""
    cfg = Config()

    if not cfg.cuckoo.version_check:
        return

    print(" Checking for updates...")

    url = "http://api.cuckoosandbox.org/checkversion.php"
    data = urllib.urlencode({"version": CUCKOO_VERSION})

    try:
        request = urllib2.Request(url, data)
        response = urllib2.urlopen(request)
    except (urllib2.URLError, urllib2.HTTPError):
        print(red(" Failed! ") + "Unable to establish connection.\n")
        return

    try:
        response_data = json.loads(response.read())
    except ValueError:
        print(red(" Failed! ") + "Invalid response.\n")
        return

    if not response_data["error"]:
        if response_data["response"] == "NEW_VERSION":
            msg = "Cuckoo Sandbox version {0} is available " \
                  "now.\n".format(response_data["current"])
            print(red(" Outdated! ") + msg)
        else:
            print(green(" Good! ") + "You have the latest version "
                                     "available.\n")


class DatabaseHandler(logging.Handler):
    """Logging to database handler.
    Used to log errors related to tasks in database.
    """

    def emit(self, record):
        if hasattr(record, "task_id"):
            db = Database()
            db.add_error(record.msg, int(record.task_id))

class ConsoleHandler(logging.StreamHandler):
    """Logging to console handler."""

    def emit(self, record):
        colored = copy.copy(record)

        if record.levelname == "WARNING":
            colored.msg = yellow(record.msg)
        elif record.levelname == "ERROR" or record.levelname == "CRITICAL":
            colored.msg = red(record.msg)
        else:
            if "analysis procedure completed" in record.msg:
                colored.msg = cyan(record.msg)
            else:
                colored.msg = record.msg

        logging.StreamHandler.emit(self, colored)

def init_logging():
    """Initializes logging."""
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    fh = logging.handlers.WatchedFileHandler(os.path.join(CUCKOO_ROOT, "log", "cuckoo.log"))
    fh.setFormatter(formatter)
    log.addHandler(fh)

    ch = ConsoleHandler()
    ch.setFormatter(formatter)
    log.addHandler(ch)

    dh = DatabaseHandler()
    dh.setLevel(logging.ERROR)
    log.addHandler(dh)

    log.setLevel(logging.INFO)

def init_console_logging():
    """Initializes logging only to console."""
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    ch = ConsoleHandler()
    ch.setFormatter(formatter)
    log.addHandler(ch)

    log.setLevel(logging.INFO)

def init_tasks():
    """Check tasks and reschedule uncompleted ones."""
    db = Database()
    cfg = Config()

    log.debug("Checking for locked tasks...")
    tasks = db.list_tasks(status=TASK_RUNNING)

    for task in tasks:
        if cfg.cuckoo.reschedule:
            db.reschedule(task.id)
            log.info("Rescheduled task with ID {0} and "
                     "target {1}".format(task.id, task.target))
        else:
            db.set_status(task.id, TASK_FAILED_ANALYSIS)
            log.info("Updated running task ID {0} status to failed_analysis".format(task.id))

def init_modules(machinery=True):
    """Initializes plugins."""
    log.debug("Importing modules...")

    # Import all auxiliary modules.
    import modules.auxiliary
    import_package(modules.auxiliary)

    # Import all processing modules.
    import modules.processing
    import_package(modules.processing)

    # Import all signatures.
    import modules.signatures
    import_package(modules.signatures)

    # Import all reporting modules.
    import modules.reporting
    import_package(modules.reporting)

    # Import machine manager.
    if machinery:
        import_plugin("modules.machinery." + Config().cuckoo.machinery)

    for category, entries in list_plugins().items():
        log.debug("Imported \"%s\" modules:", category)

        for entry in entries:
            if entry == entries[-1]:
                log.debug("\t `-- %s", entry.__name__)
            else:
                log.debug("\t |-- %s", entry.__name__)

def init_yara():
    """Generates index for yara signatures."""

    def find_signatures(root):
        signatures = []
        for entry in os.listdir(root):
            if entry.endswith(".yara") or entry.endswith(".yar"):
                signatures.append(os.path.join(root, entry))

        return signatures

    log.debug("Initializing Yara...")

    # Generate root directory for yara rules.
    yara_root = os.path.join(CUCKOO_ROOT, "data", "yara")

    # We divide yara rules in three categories.
    categories = ["binaries", "urls", "memory"]
    generated = []
    # Loop through all categories.
    for category in categories:
        # Check if there is a directory for the given category.
        category_root = os.path.join(yara_root, category)
        if not os.path.exists(category_root):
            continue

        # Check if the directory contains any rules.
        signatures = []
        for entry in os.listdir(category_root):
            if entry.endswith(".yara") or entry.endswith(".yar"):
                signatures.append(os.path.join(category_root, entry))

        if not signatures:
            continue

        # Generate path for the category's index file.
        index_name = "index_{0}.yar".format(category)
        index_path = os.path.join(yara_root, index_name)

        # Create index file and populate it.
        with open(index_path, "w") as index_handle:
            for signature in signatures:
                index_handle.write("include \"{0}\"\n".format(signature))

        generated.append(index_name)

    for entry in generated:
        if entry == generated[-1]:
            log.debug("\t `-- %s", entry)
        else:
            log.debug("\t |-- %s", entry)

def init_binaries():
    """Inform the user about the need to periodically look for new analyzer
    binaries. These include the Windows monitor etc."""
    windows = os.path.join("analyzer", "windows", "bin")

    binaries = [
        os.path.join(windows, "monitor-x86.dll"),
        os.path.join(windows, "monitor-x64.dll"),
        os.path.join(windows, "inject-x86.exe"),
        os.path.join(windows, "inject-x64.exe"),
        os.path.join(windows, "is32bit.exe"),
    ]

    update = False

    for path in binaries:
        if not os.path.exists(path):
            log.warning("The binary %s, required for Windows analysis, "
                        "is missing.", path)
            update = True
            continue

        if HAVE_PEFILE:
            timestamp = pefile.PE(path).FILE_HEADER.TimeDateStamp
        else:
            timestamp = os.path.getctime(path)

        filetime = datetime.fromtimestamp(timestamp)
        one_week = datetime.now() - timedelta(days=7)

        if filetime < one_week:
            update = True
            log.warning("The binary %s is more than a week old!", path)

    if update:
        log.critical("It is recommended that you update the binaries used "
                     "for Windows analysis (if you have not done so already, "
                     "it is possible that there was no update - in that case "
                     "this error will persist). To do so, please run the "
                     "following command: ./utils/community.py -wafb monitor")

def cuckoo_clean():
    """Clean up cuckoo setup.
    It deletes logs, all stored data from file system and configured databases (SQL
    and MongoDB.
    """
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.
    create_structure()
    init_console_logging()

    # Initialize the database connection.
    try:
        db = Database(schema_check=False)
    except CuckooDatabaseError as e:
        # If something is screwed due to incorrect database migrations or bad
        # database SqlAlchemy would be unable to connect and operate.
        log.warning("Error connecting to database: it is suggested to check "
                    "the connectivity, apply all migrations if needed or purge "
                    "it manually. Error description: %s", e)
    else:
        # Drop all tables.
        db.drop()

    # Check if MongoDB reporting is enabled and drop that if it is.
    cfg = Config("reporting")
    if cfg.mongodb and cfg.mongodb.enabled:
        from pymongo import MongoClient
        host = cfg.mongodb.get("host", "127.0.0.1")
        port = cfg.mongodb.get("port", 27017)
        mdb = cfg.mongodb.get("db", "cuckoo")
        try:
            conn = MongoClient(host, port)
            conn.drop_database(mdb)
            conn.close()
        except:
            log.warning("Unable to drop MongoDB database: %s", mdb)

    # Paths to clean.
    paths = [
        os.path.join(CUCKOO_ROOT, "db"),
        os.path.join(CUCKOO_ROOT, "log"),
        os.path.join(CUCKOO_ROOT, "storage"),
    ]

    # Delete various directories.
    for path in paths:
        if os.path.isdir(path):
            try:
                shutil.rmtree(path)
            except (IOError, OSError) as e:
                log.warning("Error removing directory %s: %s", path, e)

    # Delete all compiled Python objects ("*.pyc").
    for dirpath, dirnames, filenames in os.walk(CUCKOO_ROOT):
        for fname in filenames:
            if not fname.endswith(".pyc"):
                continue

            path = os.path.join(CUCKOO_ROOT, dirpath, fname)

            try:
                os.unlink(path)
            except (IOError, OSError) as e:
                log.warning("Error removing file %s: %s", path, e)

def drop_privileges(username):
    """Drops privileges to selected user.
    @param username: drop privileges to this username
    """
    try:
        user = pwd.getpwnam(username)
        os.setgroups((user.pw_gid,))
        os.setgid(user.pw_gid)
        os.setuid(user.pw_uid)
        os.putenv("HOME", user.pw_dir)
    except KeyError:
        sys.exit("Invalid user specified to drop privileges to: %s" % user)
    except OSError as e:
        sys.exit("Failed to drop privileges to %s: %s" % (username, e))
