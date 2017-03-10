#!/usr/bin/env python
# Copyright (C) 2015-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import IPython
import os.path
import sys

from cuckoo.core.database import *
from cuckoo.misc import decide_cwd

if __name__ == "__main__":
    decide_cwd(exists=True)

    db = Database()
    db.connect()
    db.engine.echo = True
    s = db.Session()

    IPython.start_ipython(user_ns=locals())
