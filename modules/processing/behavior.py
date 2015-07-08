# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import collections

from lib.cuckoo.common.abstracts import Processing, BehaviorHandler
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.utils import ThreadSingleton, subdict, jsonset
from .platform.windows import WindowsMonitor
from .platform.linux import LinuxSystemTap

log = logging.getLogger(__name__)

class Summary(BehaviorHandler):
    """Generates overview summary information (not split by process)."""

    key = "summary"
    event_types = ["generic"]

    def __init__(self, *args, **kwargs):
        super(Summary, self).__init__(*args, **kwargs)
        self.results = collections.defaultdict(jsonset)

    def handle_event(self, event):
        self.results[event["category"]].append(event["value"])

    def run(self):
        return self.results

class Anomaly(BehaviorHandler):
    """Anomaly detected during analysis.
    For example: a malware tried to remove Cuckoo's hooks.
    """

    key = "anomaly"
    event_types = ["anomaly"]

    def __init__(self, *args, **kwargs):
        super(Anomaly, self).__init__(*args, **kwargs)
        self.anomalies = []

    def handle_event(self, call):
        """Process API calls.
        @param call: API call object
        @param process: process object
        """

        category, funcname, message = None, None, None
        for row in call["arguments"]:
            if row["name"] == "Subcategory":
                category = row["value"]
            if row["name"] == "FunctionName":
                funcname = row["value"]
            if row["name"] == "Message":
                message = row["value"]

        self.anomalies.append(dict(
            #name=process["process_name"],
            #pid=process["process_id"],
            category=category,
            funcname=funcname,
            message=message,
        ))

    def run(self):
        """Fetch all anomalies."""
        return self.anomalies

class ProcessTree(BehaviorHandler):
    """Generates process tree."""

    key = "processtree"
    event_types = ["process"]

    def __init__(self, *args, **kwargs):
        super(ProcessTree, self).__init__(*args, **kwargs)
        self.processes = {}

    def handle_event(self, process):
        if process["pid"] in self.processes:
            return

        pcopy = subdict(process, ["pid", "process_name", "first_seen", "ppid"])
        pcopy["children"] = []

        self.processes[process["pid"]] = pcopy

    def run(self):
        root = {"children": []}

        for p in self.processes.values():
            self.processes.get(p["ppid"], root)["children"].append(p)

        return root["children"]

class GenericBehavior(BehaviorHandler):
    """Generates summary information."""

    key = "generic"
    event_types = ["process", "generic"]

    def __init__(self, *args, **kwargs):
        super(GenericBehavior, self).__init__(*args, **kwargs)
        self.processes = {}

    def handle_process_event(self, process):
        if process["pid"] in self.processes:
            return

        pcopy = subdict(process, ["pid", "process_name", "first_seen", "ppid"])
        pcopy["summary"] = collections.defaultdict(jsonset)

        self.processes[process["pid"]] = pcopy

    def handle_generic_event(self, event):
        if event["pid"] in self.processes:
            # TODO: rewrite / generalize / more flexible
            self.processes[event["pid"]]["summary"][event["category"]].append(event["value"])
        else:
            log.warning("Generic event for unknown process id %u", event["pid"])

    def run(self):
        return self.processes.values()

class ApiStats(BehaviorHandler):
    """Counts API calls."""

    key = "apistats"
    event_types = ["apicall"]

    def __init__(self, *args, **kwargs):
        super(ApiStats, self).__init__(*args, **kwargs)
        self.processes = collections.defaultdict(lambda: collections.defaultdict(lambda: 0))

    def handle_event(self, event):
        self.processes[event["pid"]][event["api"]] += 1

    def run(self):
        return self.processes

class PlatformInfo(BehaviorHandler):
    """Provides information about the platform for the collected behavior.

    Not sure if this is really needed, as probably all the info is in the results["info"] area.
    """
    key = "platform"

        # self.results = {
        #     "name": "windows",
        #     "architecture": "unknown", # look this up in the task / vm info?
        #     "source": ["monitor", "windows"],
        # }

class BehaviorAnalysis(Processing):
    """Behavior Analyzer.

    The behavior key in the results dict will contain both default content keys
    that contain generic / abstracted analysis info, available on any platform,
    as well as platform / analyzer specific output.

    Typically the analyzer behavior contains some sort of "process" separation as
    we're tracking different processes in most cases.

    So this looks roughly like this:
    "behavior": {
        "generic": {
            "processes": [
                {
                    "pid": x,
                    "ppid": y,
                    "calls": [
                        {
                            "function": "foo",
                            "arguments": {
                                "a": 1,
                                "b": 2,
                            },
                        },
                        ...
                    ]
                },
                ...
            ]
        }
        "summary": {
            "
        }
        "platform": {
            "name": "windows",
            "architecture": "x86",
            "source": ["monitor", "windows"],
            ...
        }
    }

    There are several handlers that produce the respective keys / subkeys. Overall
    the platform / analyzer specific ones parse / process the captured data and yield
    both their own output, but also a standard structure that is then captured by the
    "generic" handlers so they can generate the standard result structures.

    The resulting structure contains some iterator onions for the monitored function calls
    that stream the content when some sink (reporting, signatures) needs it, thereby
    reducing memory footprint.

    So hopefully in the end each analysis should be fine with 2 passes over the results,
    once during processing (creating the generic output, summaries, etc) and once
    during reporting (well once for each report type if multiple are enabled).
    """

    key = "behavior"

    def _enum_logs(self):
        """Enumerate all behavior logs."""
        if not os.path.exists(self.logs_path):
            log.warning("Analysis results folder does not exist at path %r.", self.logs_path)
            return

        logs = os.listdir(self.logs_path)
        if not logs:
            log.warning("Analysis results folder does not contain any behavior log files.")
            return

        for fname in logs:
            path = os.path.join(self.logs_path, fname)
            if not os.path.isfile(path):
                log.warning("Behavior log file %r is not a file.", fname)
                continue

            analysis_size_limit = self.cfg.processing.analysis_size_limit
            if analysis_size_limit and \
                    os.stat(path).st_size > analysis_size_limit:
                # This needs to be a big alert.
                log.critical("Behavior log file %r is too big, skipped.", fname)
                continue

            yield path

    def run(self):
        """Run analysis.
        @return: results dict.
        """
        self.cfg = Config()
        self.state = {}

        # these handlers will be present for any analysis, regardless of platform/format
        handlers = [
            GenericBehavior(self),
            ProcessTree(self),
            Summary(self),
            Anomaly(self),
            ApiStats(self),

            # platform specific stuff
            WindowsMonitor(self),
            LinuxSystemTap(self),
        ]

        # doesn't really work if there's no task, let's rely on the file name for now
        # # certain handlers only makes sense for a specific platform
        # # this allows us to use the same filenames/formats without confusion
        # if self.task.machine.platform == "windows":
        #     handlers += [
        #         WindowsMonitor(self),
        #     ]
        # elif self.task.machine.platform == "linux":
        #     handlers += [
        #         LinuxSystemTap(self),
        #     ]

        # create a lookup map
        interest_map = {}
        for h in handlers:
            for event_type in h.event_types:
                if not event_type in interest_map: interest_map[event_type] = []
                interest_map[event_type].append(h)

        ### PARTY

        # Each log file should be parsed by one of the handlers. This handler
        # then yields every event in it which are forwarded to the various
        # behavior/analysis/etc handlers.
        for path in self._enum_logs():
            for handler in handlers:
                # ... whether it is responsible
                if not handler.handles_path(path):
                    continue

                # ... and then let it parse the file
                for event in handler.parse(path):
                    # pass down the parsed message to interested handlers
                    for ihandler in interest_map.get(event["type"], []):
                        res = ihandler.handle_event(event)
                        # we support one layer of "generating" new events, which we'll pass on again
                        #  (in case the handler returns some)
                        if not res:
                            continue

                        for subevent in res:
                            for ihandler2 in interest_map.get(subevent["type"], []):
                                ihandler2.handle_event(subevent)

        ### END OF PARTY

        behavior = {}

        for handler in handlers:
            try:
                r = handler.run()
                if r is False:
                    continue
                behavior[handler.key] = r
            except:
                log.exception("Failed to run partial behavior class \"%s\"", handler.key)

        return behavior
