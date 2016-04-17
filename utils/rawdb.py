#!/usr/bin/env python
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import IPython
import os.path
import sys

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from cuckoo.core.database import *
from cuckoo.misc import set_cwd

if __name__ == "__main__":
    set_cwd(os.path.expanduser("~/.cuckoo"))

    db = Database()
    db.connect()
    db.engine.echo = True
    s = db.Session()

    IPython.start_ipython(user_ns=locals())
