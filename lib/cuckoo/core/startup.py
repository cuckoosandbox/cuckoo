import os
import sys

def check_dependencies():
    dependencies = ["sqlite3"]

    for dependency in dependencies:
        try:
            __import__(dependency)
        except ImportError as e:
            sys.exit("Unable to import \"%s\"." % dependency)

    return True

def create_folders(root="."):
    folders = ["db/",
               "log/",
               "storage/",
               "storage/analyses/",
               "storage/binaries/"]

    for folder in folders:
        if os.path.exists(folder):
            continue

        try:
            folder_path = os.path.join(root, folder)
            os.mkdir(folder_path)
        except OSError as e:
            continue
