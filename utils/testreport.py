import sys

sys.path.append("../")

from lib.cuckoo.core.processor import Processor
from lib.cuckoo.core.reporter import Reporter

Reporter(sys.argv[1]).run(Processor(sys.argv[1]).run())
