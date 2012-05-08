import os
import sys
import logging

from lib.cuckoo.common.exceptions import CuckooStartupError
from lib.cuckoo.common.utils import create_folders

log = logging.getLogger()

def check_python_version():
    version = sys.version.split()[0]
    if version < "2.6" or version >= "3":
        raise CuckooStartupError("You are running an incompatible version of Python, please use 2.6 or 2.7")

def check_working_directory():
    cwd = os.path.join(os.getcwd(), "cuckoo.py")
    if not os.path.exists(cwd):
        raise CuckooStartupError("You are not running Cuckoo from it's root directory")

def check_dependencies():
    check_python_version()

    dependencies = ["sqlite3"]

    for dependency in dependencies:
        try:
            __import__(dependency)
        except ImportError as e:
            raise CuckooStartupError("Unable to import \"%s\"." % dependency)

    return True

def create_structure():
    folders = ["db/",
               "log/",
               "storage/",
               "storage/analyses/",
               "storage/binaries/"]

    create_folders(folders=folders)

def init_logging():
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    log.addHandler(sh)
    fh = logging.FileHandler("log/cuckoo.log")
    fh.setFormatter(formatter)
    log.addHandler(fh)
    log.setLevel(logging.INFO)