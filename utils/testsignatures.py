#!/usr/bin/env python
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import logging

logging.basicConfig()

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.core.processor import Processor

results = Processor(sys.argv[1]).run()

if "signatures" in results:
    for signature in results["signatures"]:
        print("%s matched:" % signature["name"])
        print("\tDescription: %s" % signature["description"])
        print("\tSeverity: %d" % signature["severity"])
