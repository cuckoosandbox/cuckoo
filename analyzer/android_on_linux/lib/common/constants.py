# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import string
import random

def _rand_string(a, b):
    return "".join(random.choice(string.ascii_lowercase) for x in xrange(random.randint(a, b)))

ROOT = os.path.join(os.getenv("HOME"), _rand_string(6, 10))

PATHS = {
    "root"   : ROOT,
    "logs"   : os.path.join(ROOT, "logs"),
    "files"  : os.path.join(ROOT, "files"),
    "shots"  : os.path.join(ROOT, "shots"),
    "memory" : os.path.join(ROOT, "memory"),
    "drop"   : os.path.join(ROOT, "drop")
}
