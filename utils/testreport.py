#!/usr/bin/env python
import os
import sys

if len(sys.argv) < 2:
    print("You need to specify the path to the analysis")
    sys.exit(1)

sys.path.append("../")

from lib.cuckoo.core.processor import Processor
from lib.cuckoo.core.reporter import Reporter

Reporter(sys.argv[1]).run(Processor(sys.argv[1]).run())
