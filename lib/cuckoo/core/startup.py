# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import json
import urllib
import urllib2
import logging
import logging.handlers

from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_VERSION
from lib.cuckoo.common.exceptions import CuckooStartupError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.utils import create_folders
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.colors import *

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

def check_dependencies():
    """Checks if dependencies are installed.
    @raise CuckooStartupError: if dependencies aren't met.
    """
    check_python_version()

    dependencies = ["sqlalchemy", "pefile"]

    for dependency in dependencies:
        try:
            __import__(dependency)
        except ImportError as e:
            raise CuckooStartupError("Unable to import \"%s\"" % dependency)

    return True

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

def init_logging():
    """Initializes logging."""
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    log.addHandler(sh)
    fh = logging.handlers.WatchedFileHandler(os.path.join(CUCKOO_ROOT, "log", "cuckoo.log"))
    fh.setFormatter(formatter)
    log.addHandler(fh)
    log.setLevel(logging.INFO)

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
