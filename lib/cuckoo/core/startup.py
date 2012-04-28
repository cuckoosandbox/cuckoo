import os
import sys

from lib.cuckoo.common.utils import create_folders

def check_dependencies():
    dependencies = ["sqlite3"]

    for dependency in dependencies:
        try:
            __import__(dependency)
        except ImportError as e:
            sys.exit("Unable to import \"%s\"." % dependency)

    return True

def create_structure():
    folders = ["db/",
               "log/",
               "storage/",
               "storage/analyses/",
               "storage/binaries/"]

    create_folders(folders=folders)
