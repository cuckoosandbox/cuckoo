import sys

sys.path.append("../")

from lib.cuckoo.core.processor import Processor

results = Processor(sys.argv[1]).run()

if "signatures" in results:
    for signature in results["signatures"]:
        print("%s matched" % signature["name"])
