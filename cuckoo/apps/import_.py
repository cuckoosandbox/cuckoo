# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path

def identify(path):
    filepath = os.path.join(path, "lib", "cuckoo", "common", "constants.py")
    if os.path.exists(filepath):
        for line in open(filepath, "rb"):
            if line.startswith("CUCKOO_VERSION"):
                return line.split('"')[1]

def import_cuckoo(path, force, database):
    pass
