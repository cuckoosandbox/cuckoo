# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import string
import random

ROOT = os.getenv("SystemDrive")+ "".join(random.choice(string.ascii_lowercase) for x in range(random.randint(5, 10)))

PATHS = {"root"   : ROOT,
         "logs"   : os.path.join(ROOT, "logs"),
         "files"  : os.path.join(ROOT, "files"),
         "shots"  : os.path.join(ROOT, "shots"),
         "memory" : os.path.join(ROOT, "memory"),
         "drop"   : os.path.join(ROOT, "drop")}

PIPE = "".join(random.choice(string.ascii_lowercase) for x in range(random.randint(5, 10)))