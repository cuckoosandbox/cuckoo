# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import logging

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooStartupError
from lib.cuckoo.common.utils import create_folders

log = logging.getLogger()

def check_python_version():
    """Checks if Python version is supported by Cuckoo.
    @raise CuckooStartupError: if version is not supported.
    """
    version = sys.version.split()[0]
    if version < "2.6" or version >= "3":
        raise CuckooStartupError("You are running an incompatible version of Python, please use 2.6 or 2.7")

def check_working_directory():
    """Checks if working directories are ready.
    @raise CuckooStartupError: if directories are not properly configured.
    """
    if not os.path.exists(CUCKOO_ROOT):
        raise CuckooStartupError("You specified a non-existing root directory: %s" % CUCKOO_ROOT)

    cwd = os.path.join(os.getcwd(), "cuckoo.py")
    if not os.path.exists(cwd):
        raise CuckooStartupError("You are not running Cuckoo from it's root directory")

def check_dependencies():
    """Checks if dependencies are installed.
    @raise CuckooStartupError: if dependencies aren't met.
    """
    check_python_version()

    dependencies = ["sqlite3"]

    for dependency in dependencies:
        try:
            __import__(dependency)
        except ImportError as e:
            raise CuckooStartupError("Unable to import \"%s\"." % dependency)

    return True

def check_configs():
    """Checks if config files exist.
    @raise CuckooStartupError: if config files do not exist.
    """
    configs = [os.path.join(CUCKOO_ROOT, "conf", "cuckoo.conf"),
               os.path.join(CUCKOO_ROOT, "conf", "reporting.conf")]

    for config in configs:
        if not os.path.exists(config):
            raise CuckooStartupError("Config file does not exist at path: %s" % config)

    return True

def create_structure():
    """Creates Cuckoo directories."""
    folders = ["db",
               "log",
               "storage",
               "storage/analyses",
               "storage/binaries"]

    create_folders(folders=folders)

def init_logging():
    """Initialize logging."""
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    log.addHandler(sh)
    fh = logging.FileHandler(os.path.join("log", "cuckoo.log"))
    fh.setFormatter(formatter)
    log.addHandler(fh)
    log.setLevel(logging.INFO)
