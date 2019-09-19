# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import logging
import dateutil.parser

from cuckoo.common.abstracts import BehaviorHandler
from cuckoo.common.utils import byteify

log = logging.getLogger(__name__)

class AndroidFileMonitor(BehaviorHandler):
    """Parse filemon logs."""

    def __init__(self, *args, **kwargs):
        super(AndroidFileMonitor, self).__init__(*args, **kwargs)
    
    def handles_path(self, path):
        if path.endswith("filemon"):
            return True

    def parse(self, path):
        for line in open(path, "r"):
            event = json.loads(line)
            for key, value in event.items():
                yield {
                    "type": "generic",
                    "pid": int(os.path.basename(path).split(".")[0]),
                    "category": key,
                    "value": value
                }

    def run(self):
        pass

class AndroidRuntime(BehaviorHandler):
    """Parse Java virtual machine logs."""

    key = "processes"

    def __init__(self, *args, **kwargs):
        super(AndroidRuntime, self).__init__(*args, **kwargs)

        self.processes = []
        self.matched = False

    def handles_path(self, path):
        if path.endswith("jvmHook"):
            self.matched = True
            return True

    def parse(self, path):
        parser = JVMHookParser(open(path, "r"))
        calls = []
        for event in parser:
            if event["type"] == "proc_info":
                process = event
            elif event["type"] == "apicall":
                calls.append(event)

            del event["type"]

        process.update({
            "type": "process",
            "pid": int(os.path.basename(path).split(".")[0]),
            "command_line": "",
            "calls": calls,
            "is_java_process": True,
        })
        self.processes.append(process)
        return self.processes

    def run(self):
        if not self.matched:
            return

        self.processes.sort(key=lambda process: process["first_seen"])
        return self.processes

class JVMHookParser(object):

    def __init__(self, fd):
        self.fd = fd

    def make_arguments(self, args):
        p_args = {}
        for n in range(len(args)):
            arg_value = args[n]
            p_args["p%u" % n] = arg_value

        return p_args

    def __iter__(self):
        proc_info = byteify(json.loads(self.fd.readline()))

        yield {
            "type": "proc_info", "ppid": proc_info["ppid"],
            "uid": proc_info["uid"], "process_name": proc_info["process_name"],
            "first_seen": dateutil.parser.parse(proc_info["first_seen"])
        }

        for line in self.fd:
            api_call = byteify(json.loads(line))

            _class = api_call["class"]
            method = api_call["method"]
            api = _class + "." + method

            time = dateutil.parser.parse(api_call["time"]).replace(tzinfo=None)
            arguments = self.make_arguments(api_call["args"])

            yield {
                "type": "apicall", "time": time, "api": api,
                "class": _class, "method": method,
                "category": api_call["category"], "arguments": arguments,
                "thisObject": api_call["thisObject"],
                "return_value": api_call["returnValue"]
            }
