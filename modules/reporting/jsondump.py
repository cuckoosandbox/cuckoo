import os
import json

from lib.cuckoo.common.abstracts import Report

class JsonDump(Report):
    def run(self, results):
        try:
            report = open(os.path.join(self.reports_path, "report.json"), "w")
            report.write(json.dumps(results, sort_keys=False, indent=4))
            report.close()
        except TypeError, why:
            print "Failed to create JSON: %s" % why
        except IOError, why:
            print "Failed writing JSON report: %s" % why

