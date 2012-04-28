import os
import json

from lib.cuckoo.abstract.report import Report

class JsonDump(Report):
    def run(self, results):
        report = open(os.path.join(self.reports_path, "report.json"), "w")
        report.write(json.dumps(results, sort_keys=False, indent=4))
        report.close()
