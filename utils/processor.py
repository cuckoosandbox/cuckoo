#!/usr/bin/env python
import os
import sys

sys.path.append("../")

from lib.cuckoo.processing.processor import Processor
from lib.cuckoo.reporting.reporter import Reporter

Reporter(sys.argv[1]).run(Processor(sys.argv[1]).run())
