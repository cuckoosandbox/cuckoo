# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
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
import socket

import cuckoo

from cuckoo.common.colors import red, green, yellow, cyan
from cuckoo.common.config import Config
from cuckoo.common.constants import CUCKOO_VERSION
from cuckoo.common.exceptions import CuckooStartupError, CuckooDatabaseError
from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.common.utils import create_folders
from cuckoo.core.database import Database, TASK_RUNNING
from cuckoo.core.database import TASK_FAILED_ANALYSIS, TASK_PENDING
from cuckoo.core.rooter import rooter, vpns
from cuckoo.misc import cwd

try:
    import pwd
    HAVE_PWD = True
except ImportError:
    HAVE_PWD = False

log = logging.getLogger(__name__)

def check_python_version():
    """Checks if Python version is supported by Cuckoo.
    @raise CuckooStartupError: if version is not supported.
    """
    if sys.version_info[:2] != (2, 7):
        raise CuckooStartupError("You are running an incompatible version "
                                 "of Python, please use 2.7")


def check_configs():
    """Checks if config files exist.
    @raise CuckooStartupError: if config files do not exist.
    """
    configs = (
        "auxiliary.conf", "avd.conf", "cuckoo.conf", "esx.conf", "kvm.conf",
        "memory.conf", "physical.conf", "processing.conf", "qemu.conf",
        "reporting.conf", "virtualbox.conf", "vmware.conf", "vpn.conf",
        "vsphere.conf", "xenserver.conf",
    )

    for filename in configs:
        if not os.path.exists(cwd("conf", filename)):
            raise CuckooStartupError(
                "Config file does not exist at path: %s" %
                cwd("conf", filename)
            )

    return True

def create_structure():
    """Creates Cuckoo directories."""
    folders = [
        "log",
        "storage",
        os.path.join("storage", "analyses"),
        os.path.join("storage", "binaries"),
        os.path.join("storage", "baseline"),
    ]

    try:
        create_folders(root=cwd(), folders=folders)
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
        r = json.loads(response.read())
    except ValueError:
        print(red(" Failed! ") + "Invalid response.\n")
        return

    if not r["error"]:
        if r["response"] == "NEW_VERSION" and r["current"] != "1.2":
            msg = "Cuckoo Sandbox version %s is available now." % r["current"]
            print(red(" Outdated! ") + msg)
        elif r["current"] == "1.2":
            print(yellow(" Okay! ") + "You are running a development version.")
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

def init_logging(level):
    """Initializes logging."""
    formatter = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
    )

    # We operate on the root logger.
    log = logging.getLogger()

    fh = logging.handlers.WatchedFileHandler(cwd("log", "cuckoo.log"))
    fh.setFormatter(formatter)
    log.addHandler(fh)

    ch = ConsoleHandler()
    ch.setFormatter(formatter)
    log.addHandler(ch)

    dh = DatabaseHandler()
    dh.setLevel(logging.ERROR)
    log.addHandler(dh)

    log.setLevel(level)

def init_console_logging(level=logging.INFO):
    """Initializes logging only to console."""
    formatter = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
    )

    # We operate on the root logger.
    log = logging.getLogger()

    ch = ConsoleHandler()
    ch.setFormatter(formatter)
    log.addHandler(ch)

    log.setLevel(level)

def init_tasks():
    """Check tasks and reschedule uncompleted ones."""
    db = Database()
    cfg = Config()

    log.debug("Checking for locked tasks..")
    for task in db.list_tasks(status=TASK_RUNNING):
        if cfg.cuckoo.reschedule:
            db.reschedule(task.id)
            log.info("Rescheduled task with ID {0} and "
                     "target {1}".format(task.id, task.target))
        else:
            db.set_status(task.id, TASK_FAILED_ANALYSIS)
            log.info("Updated running task ID {0} status to failed_analysis".format(task.id))

    log.debug("Checking for pending service tasks..")
    for task in db.list_tasks(status=TASK_PENDING, category="service"):
        db.set_status(task.id, TASK_FAILED_ANALYSIS)

def delete_file(*rel_path):
    filepath = cwd(*rel_path)
    if not os.path.exists(filepath):
        return

    try:
        os.unlink(filepath)
    except Exception as e:
        log.warning(
            "Unable to remove old %s leftover file from before you updated "
            "your Cuckoo setup to the latest version: %s.",
            os.path.join(*rel_path), e
        )

def init_modules():
    """Initializes plugins."""
    log.debug("Imported modules...")

    for category, entries in cuckoo.plugins.items():
        log.debug("Imported \"%s\" modules:", category)

        for entry in entries:
            if entry == entries[-1]:
                log.debug("\t `-- %s", entry.__name__)
            else:
                log.debug("\t |-- %s", entry.__name__)

def init_yara():
    """Generates index for yara signatures."""
    log.debug("Initializing Yara...")

    # Generate root directory for yara rules.
    yara_root = cwd("yara")

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
    monitor = cwd("monitor", "latest")

    # Checks whether the "latest" symlink is available as well as whether
    # it points to an existing directory.
    if not os.path.exists(monitor):
        raise CuckooStartupError(
            "The binaries used for Windows analysis are updated regularly, "
            "independently from the release line. It appears that you're "
            "not up-to-date. This may happen when you've just installed the "
            "latest development version of Cuckoo or when you've updated "
            "to the latest Cuckoo. In order to get up-to-date, please run "
            "the following command: `cuckoo community`."
        )

def init_rooter():
    """If required, check whether the rooter is running and whether we can
    connect to it."""
    cuckoo = Config()

    # The default configuration doesn't require the rooter to be ran.
    if not Config("vpn").vpn.enabled and cuckoo.routing.route == "none":
        return

    cuckoo = Config()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    try:
        s.connect(cuckoo.cuckoo.rooter)
    except socket.error as e:
        if e.strerror == "No such file or directory":
            raise CuckooStartupError(
                "The rooter is required but it is either not running or it "
                "has been configured to a different Unix socket path. "
                "(In order to disable the use of rooter, please set route "
                "and internet to none in cuckoo.conf and enabled to no in "
                "vpn.conf)."
            )

        if e.strerror == "Connection refused":
            raise CuckooStartupError(
                "The rooter is required but we can't connect to it as the "
                "rooter is not actually running. "
                "(In order to disable the use of rooter, please set route "
                "and internet to none in cuckoo.conf and enabled to no in "
                "vpn.conf)."
            )

        if e.strerror == "Permission denied":
            raise CuckooStartupError(
                "The rooter is required but we can't connect to it due to "
                "incorrect permissions. Did you assign it the correct group? "
                "(In order to disable the use of rooter, please set route "
                "and internet to none in cuckoo.conf and enabled to no in "
                "vpn.conf)."
            )

        raise CuckooStartupError("Unknown rooter error: %s" % e)

    # Do not forward any packets unless we have explicitly stated so.
    rooter("forward_drop")

def init_routing():
    """Initialize and check whether the routing information is correct."""
    cuckoo = Config()
    vpn = Config("vpn")

    # Check whether all VPNs exist if configured and make their configuration
    # available through the vpns variable. Also enable NAT on each interface.
    if vpn.vpn.enabled:
        for name in vpn.vpn.vpns.split(","):
            name = name.strip()
            if not name:
                continue

            if not hasattr(vpn, name):
                raise CuckooStartupError(
                    "Could not find VPN configuration for %s" % name
                )

            entry = vpn.get(name)

            if not rooter("nic_available", entry.interface):
                raise CuckooStartupError(
                    "The network interface that has been configured for "
                    "VPN %s is not available." % entry.name
                )

            if not rooter("rt_available", entry.rt_table):
                raise CuckooStartupError(
                    "The routing table that has been configured for "
                    "VPN %s is not available." % entry.name
                )

            vpns[entry.name] = entry

            # Disable & enable NAT on this network interface. Disable it just
            # in case we still had the same rule from a previous run.
            rooter("disable_nat", entry.interface)
            rooter("enable_nat", entry.interface)

            # Populate routing table with entries from main routing table.
            if cuckoo.routing.auto_rt:
                rooter("flush_rttable", entry.rt_table)
                rooter("init_rttable", entry.rt_table, entry.interface)

    # Check whether the default VPN exists if specified.
    if cuckoo.routing.route not in ("none", "internet"):
        if not vpn.vpn.enabled:
            raise CuckooStartupError(
                "A VPN has been configured as default routing interface for "
                "VMs, but VPNs have not been enabled in vpn.conf"
            )

        if cuckoo.routing.route not in vpns:
            raise CuckooStartupError(
                "The VPN defined as default routing target has not been "
                "configured in vpn.conf."
            )

    # Check whether the dirty line exists if it has been defined.
    if cuckoo.routing.internet != "none":
        if not rooter("nic_available", cuckoo.routing.internet):
            raise CuckooStartupError(
                "The network interface that has been configured as dirty "
                "line is not available."
            )

        if not rooter("rt_available", cuckoo.routing.rt_table):
            raise CuckooStartupError(
                "The routing table that has been configured for dirty "
                "line interface is not available."
            )

        # Disable & enable NAT on this network interface. Disable it just
        # in case we still had the same rule from a previous run.
        rooter("disable_nat", cuckoo.routing.internet)
        rooter("enable_nat", cuckoo.routing.internet)

        # Populate routing table with entries from main routing table.
        if cuckoo.routing.auto_rt:
            rooter("flush_rttable", cuckoo.routing.rt_table)
            rooter("init_rttable", cuckoo.routing.rt_table,
                   cuckoo.routing.internet)

def cuckoo_clean():
    """Clean up cuckoo setup.
    It deletes logs, all stored data from file system and configured
    databases (SQL and MongoDB).
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
        cwd("cuckoo.db"),
        cwd("log"),
        cwd("storage"),
    ]

    # Delete various directories.
    for path in paths:
        if os.path.isdir(path):
            try:
                shutil.rmtree(path)
            except (IOError, OSError) as e:
                log.warning("Error removing directory %s: %s", path, e)
        elif os.path.isfile(path):
            try:
                os.unlink(path)
            except (IOError, OSError) as e:
                log.warning("Error removing file %s: %s", path, e)

def drop_privileges(username):
    """Drops privileges to selected user.
    @param username: drop privileges to this username
    """
    if not HAVE_PWD:
        sys.exit("Unable to import pwd required for dropping "
                 "privileges (`pip install pwd`)")

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
