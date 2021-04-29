# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import calendar
import datetime
import json
import os

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooReportError


def default(obj):
    if isinstance(obj, datetime.datetime):
        if obj.utcoffset() is not None:
            obj = obj - obj.utcoffset()
        return calendar.timegm(obj.timetuple()) + obj.microsecond / 1000000.0
    raise TypeError("%r is not JSON serializable" % obj)


class JsonDump(Report):
    """Save analysis results in JSON format."""

    def erase_calls(self, results):
        """Temporarily remove calls from the report by replacing them with
        empty lists. Or limiting calls that are made way too often."""

        self.calls_to_be_restored = {}
        if self.calls and self.call_limit:
            # Create dict of {pid: {call that needs to be limited: current count, ...}, ...}
            calls_to_be_limited = {}
            behaviour = results.get("behavior", {})
            apistats = behaviour.get("apistats", {})

            # First fill calls_to_be_limited with... calls that need to be limited!
            for pid in apistats:
                calls_to_be_limited[pid] = {}
                calls = apistats[pid]
                for call in calls:
                    call_count = calls[call]
                    # If the number of calls according to apistats is too high,
                    # then start a counter
                    if call_count >= self.call_limit:
                        calls_to_be_limited[pid][str(call)] = 0

            # Now that we have the pid + api call to limit relationship, we can apply it to processes
            for process in behaviour.get("processes", []):
                pid = str(process["pid"])
                process_calls = process["calls"]
                self.calls_to_be_restored[pid] = process_calls

                # If a process has no calls that need to be limited, move on
                if pid not in calls_to_be_limited or not calls_to_be_limited.get(pid, {}):
                    continue

                calls_to_be_limited_for_pid = calls_to_be_limited[pid]
                limited_calls = []
                for call in process_calls:
                    api = str(call["api"])
                    # Skip call if over limit
                    if api in calls_to_be_limited_for_pid and calls_to_be_limited_for_pid[api] >= self.call_limit:
                        continue
                    # Increment count if call is to be limited
                    elif api in calls_to_be_limited_for_pid:
                        calls_to_be_limited_for_pid[api] += 1
                    limited_calls.append(call)
                process["calls"] = limited_calls
            return
        elif self.calls and not self.call_limit:
            # This means we want all calls, and don't need to restore anything
            self.calls = False
            return
        else:
            # This means we don't want calls in jsondump, therefore all calls need to be restored
            for process in results.get("behavior", {}).get("processes", []):
                pid = str(process["pid"])
                self.calls_to_be_restored[pid] = process["calls"]
                process["calls"] = []

    def restore_calls(self, results):
        """Restore calls that were temporarily removed in the report by
        replacing the calls with the original values."""
        if not self.calls:
            return

        for process in results.get("behavior", {}).get("processes", []):
            process["calls"] = self.calls_to_be_restored.pop(str(process["pid"]))

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        # Determine whether we want to include the behavioral data in the
        # JSON report.
        if "json.calls" in self.task["options"]:
            self.calls = int(self.task["options"]["json.calls"])
        else:
            self.calls = self.options.get("calls", True)

        if "json.call_limit" in self.task["options"]:
            self.call_limit = int(self.task["options"]["json.call_limit"])
        else:
            self.call_limit = self.options.get("call_limit", 0)

        # Attempting to write report without behaviour
        self.erase_calls(results)
        try:
            filepath = os.path.join(self.reports_path, "report.json")
            with open(filepath, "wb", buffering=1024*1024) as report:
                json.dump(
                    results, report, default=default, sort_keys=False,
                    indent=self.options.indent, encoding="latin-1"
                )
        except (TypeError, IOError) as e:
            raise CuckooReportError("Failed to generate JSON report: %s" % e)
        finally:
            self.restore_calls(results)
