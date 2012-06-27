#!/usr/bin/env python
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import logging

logging.basicConfig()

sys.path.append("..")

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.processor import Processor
from lib.cuckoo.core.reporter import Reporter

if CUCKOO_ROOT == "." or not os.path.exists(CUCKOO_ROOT):
    print("ERROR: you need to specify a valid absolute root directory in lib/cuckoo/common/constants.py")
else:
    Reporter(sys.argv[1]).run(Processor(sys.argv[1]).run())
