# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import copy
import json
import urllib
import urllib2
import pkgutil
import logging
import logging.handlers

import modules.processing
import modules.signatures
import modules.reporting

from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_VERSION
from lib.cuckoo.common.exceptions import CuckooStartupError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.utils import create_folders
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.colors import *
from lib.cuckoo.core.plugins import import_plugin, import_package, list_plugins
from lib.cuckoo.core.database import Database

try:
    import graypy
    HAVE_GRAYPY = True
except ImportError:
    HAVE_GRAYPY = False

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
                                 "directory: %s" % CUCKOO_ROOT)

    cwd = os.path.join(os.getcwd(), "cuckoo.py")
    if not os.path.exists(cwd):
        raise CuckooStartupError("You are not running Cuckoo from it's "
                                 "root directory")

def check_configs():
    """Checks if config files exist.
    @raise CuckooStartupError: if config files do not exist.
    """
    configs = [os.path.join(CUCKOO_ROOT, "conf", "cuckoo.conf"),
               os.path.join(CUCKOO_ROOT, "conf", "reporting.conf")]

    for config in configs:
        if not os.path.exists(config):
            raise CuckooStartupError("Config file does not exist at path: %s"
                                     % config)

    return True

def create_structure():
    """Creates Cuckoo directories."""
    folders = ["log",
               "storage",
               os.path.join("storage", "analyses"),
               os.path.join("storage", "binaries")]

    try:
        create_folders(root=CUCKOO_ROOT,folders=folders)
    except CuckooOperationalError as e:
        raise CuckooStartupError(e)

def check_version():
    """Checks version of Cuckoo."""
    cfg = Config()

    if not cfg.cuckoo.version_check:
        return

    print(" Checking for updates...")

    url = "http://api.cuckoosandbox.org/checkversion.php"
    data = urllib.urlencode({"version" : CUCKOO_VERSION})

    try:
        request = urllib2.Request(url, data)
        response = urllib2.urlopen(request)
    except (urllib2.URLError, urllib2.HTTPError):
        return

    try:
        response_data = json.loads(response.read())
    except ValueError:
        return

    if not response_data["error"]:
        if response_data["response"] == "NEW_VERSION":
            print(red(" Outdated! ") + "Cuckoo Sandbox version %s is "
                  "available now.\n" % response_data["current"])
        else:
            print(green(" Good! ") + "You have the latest version available.\n")

class DatabaseHandler(logging.Handler):
    def emit(self, record):
        if hasattr(record, "task_id"):
            db = Database()
            db.add_error(record.msg, int(record.task_id))

class ConsoleHandler(logging.StreamHandler):
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
    cfg = Config()

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

    if cfg.graylog.enabled:
        if HAVE_GRAYPY:
            gray = graypy.GELFHandler(cfg.graylog.host, cfg.graylog.port)

            try:
                level = logging.getLevelName(cfg.graylog.level.upper())
            except ValueError:
                level = logging.ERROR

            gray.setLevel(level)
            log.addHandler(gray)
        else:
            raise CuckooDependencyError("Graypy is not installed")

    log.setLevel(logging.INFO)

def init_modules():
    """Initializes plugins."""
    log.debug("Importing modules...")

    # Import all processing modules.
    import_package(modules.processing)
    # Import all signatures.
    import_package(modules.signatures)

    # Import only enabled reporting modules.
    report_cfg = Config(cfg=os.path.join(CUCKOO_ROOT,
                                         "conf",
                                         "reporting.conf"))

    prefix = modules.reporting.__name__ + "."
    for loader, name, ispkg in pkgutil.iter_modules(modules.reporting.__path__):
        if ispkg:
            continue

        try:
            options = report_cfg.get(name)
        except AttributeError:
            log.debug("Reporting module %s not found in "
                      "configuration file" % module_name)

        if not options.enabled:
            continue

        import_plugin("%s.%s" % (modules.reporting.__name__, name))

    # Import machine manager.
    import_plugin("modules.machinemanagers.%s"
                  % Config().cuckoo.machine_manager)

    for category, mods in list_plugins().items():
        log.debug("Imported \"%s\" modules:" % category)

        for mod in mods:
            if mod == mods[-1]:
                log.debug("\t `-- %s" % mod.__name__)
            else:
                log.debug("\t |-- %s" % mod.__name__)
