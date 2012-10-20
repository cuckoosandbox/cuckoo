# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

system_drive = os.getenv("SystemDrive")
root = "%s%s%s%s" % (system_drive, os.sep, "cuckoo", os.sep)

PATHS = {"root"     : root,
         "logs"     : os.path.join(root, "logs"),
         "files"    : os.path.join(root, "files"),
         "shots"    : os.path.join(root, "shots"),
         "memory"   : os.path.join(root, "memory"),
         "drop"     : os.path.join(root, "drop")}
