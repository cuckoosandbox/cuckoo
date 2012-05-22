#!/usr/bin/env python
import sys
import logging

logging.basicConfig()

sys.path.append("../")

from lib.cuckoo.core.processor import Processor

results = Processor(sys.argv[1]).run()

if "signatures" in results:
    for signature in results["signatures"]:
        print("%s matched:" % signature["name"])
        print("\tDescription: %s" % signature["description"])
        print("\tSeverity: %d" % signature["severity"])
