# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import codecs
import calendar
import datetime

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

def default(obj):
    if isinstance(obj, datetime.datetime):
        if obj.utcoffset() is not None:
            obj = obj - obj.utcoffset()
        return calendar.timegm(obj.timetuple()) + obj.microsecond / 1000000.0
    raise TypeError("%r is not JSON serializable" % obj)

class JsonDump(Report):
    """Saves analysis results in JSON format."""

    def erase_calls(self, results):
        """Temporarily removes calls from the report by replacing them with
        empty lists."""
        if self.calls:
            self.calls = None
            return

        self.calls = []
        for process in results.get("behavior", {}).get("processes", []):
            self.calls.append(process["calls"])
            process["calls"] = []

    def restore_calls(self, results):
        """Restores calls that were temporarily removed in the report by
        replacing the calls with the original values."""
        if not self.calls:
            return

        for process in results.get("behavior", {}).get("processes", []):
            process["calls"] = self.calls.pop(0)

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        indent = self.options.get("indent", 4)
        encoding = self.options.get("encoding", "utf-8")

        # Determine whether we want to include the behavioral data in the
        # JSON report.
        if "json.calls" in self.task["options"]:
            self.calls = int(self.task["options"]["json.calls"])
        else:
            self.calls = self.options.get("calls", True)

        self.erase_calls(results)

        try:
            path = os.path.join(self.reports_path, "report.json")

            with codecs.open(path, "w", "utf-8") as report:
                json.dump(results, report, default=default, sort_keys=False,
                          indent=int(indent), encoding=encoding)
        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError("Failed to generate JSON report: %s" % e)
        finally:
            self.restore_calls(results)
