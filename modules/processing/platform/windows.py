# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import datetime

from lib.cuckoo.common.abstracts import BehaviorHandler
from lib.cuckoo.common.utils import convert_to_printable, logtime, cleanup_value
from lib.cuckoo.common.netlog import BsonParser

log = logging.getLogger(__name__)

class MonitorProcessLog(list):
    def __init__(self, eventstream):
        self.eventstream = eventstream
        self.first_seen = None

    def __iter__(self):
        call_id = 0
        for event in self.eventstream:
            if event["type"] == "process":
                self.first_seen = event["first_seen"]
            elif event["type"] == "call":
                event["time"] = self.first_seen + datetime.timedelta(0, 0, event["time"] * 1000)

                # backwards compat with previous reports, remove if not necessary
                # event["repeated"] = 0
                # event["timestamp"] = logtime(event.pop("time"))
                # event["arguments"] = [dict(name=i, value=j) for i,j in event["arguments"].iteritems()]
                # event["return"] = convert_to_printable(cleanup_value(event.pop("return_value")))

                # event["is_success"] = bool(int(event.pop("status")))
                # event["id"] = call_id
                # call_id += 1

                del event["type"]
                yield event

    def __nonzero__(self):
        return True

class WindowsMonitor(BehaviorHandler):
    """Parses cuckoomon/monitor generated logs."""

    key = "platform"

    def __init__(self, *args, **kwargs):
        super(WindowsMonitor, self).__init__(*args, **kwargs)
        self.results = {
            "name": "windows",
            "architecture": "unknown", # look this up in the task / vm info?
            "source": ["monitor", "windows"],
            "processes": [],
        }
        self.matched = False

    def handles_path(self, path):
        if path.endswith(".bson"):
            self.matched = True
            return True

    def parse(self, path):
        # Invoke parsing of current log file.
        parser = BsonParser(open(path, "rb"))

        for event in parser:
            if event["type"] == "process":
                process = dict(event)
                process["calls"] = MonitorProcessLog(parser)
                self.results["processes"].append(process)

            yield event

    def run(self):
        if not self.matched: return False

        self.results["processes"].sort(key=lambda process: process["first_seen"])
        return self.results
