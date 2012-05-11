import os
import json

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

class JsonDump(Report):
    def run(self, results):
        try:
            report = open(os.path.join(self.reports_path, "report.json"), "w")
            report.write(json.dumps(results, sort_keys=False, indent=4))
            report.close()
        except (TypeError, IOError) as e:
            raise CuckooReportError("Failed to generate JSON report: %s" % e.message)
