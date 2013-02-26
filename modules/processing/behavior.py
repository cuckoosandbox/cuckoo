# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import csv
import logging
import datetime
import inspect

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.utils import convert_to_printable, logtime
from lib.cuckoo.common.netlog import NetlogParser

log = logging.getLogger(__name__)

class ParseProcessLog(list):
    """Parses process log file."""
    
    def __init__(self, log_path):
        """@param log_path: log file path."""
        self._log_path = log_path
        self.fd = None
        self.parser = None

        self.process_id = None
        self.process_name = None
        self.parent_id = None
        self.first_seen = None
        self.calls = self
        self.lastcall = None

        if os.path.exists(log_path) and os.stat(log_path).st_size > 0:
            self.parse_first_and_reset()

    def parse_first_and_reset(self):
        self.fd = open(self._log_path, "rb")
        self.parser = NetlogParser(self)
        self.parser.read_next_message()
        self.fd.seek(0)

    def read(self, length):
        if length == 0: return b''
        buf = self.fd.read(length)
        if not buf or len(buf) != length: raise EOFError()
        return buf

    def __iter__(self):
        #log.debug('iter called by this guy: {0}'.format(inspect.stack()[1]))
        return self

    def __getitem__(self, key):
        return getattr(self, key)

    def __repr__(self):
        return 'ParseProcessLog {0}'.format(self._log_path)

    def __nonzero__(self):
        return True

    def next(self):
        while not self.lastcall:
            r = None
            try: r = self.parser.read_next_message()
            except EOFError:
                self.fd.seek(0)
                raise StopIteration()

            if not r: raise StopIteration()

        tmp, self.lastcall = self.lastcall, None
        return tmp

    def log_process(self, context, timestring, pid, ppid, modulepath, procname):
        self.process_id, self.parent_id, self.process_name = pid, ppid, procname
        self.first_seen = timestring

    def log_thread(self, context, pid):
        pass

    def log_call(self, context, apiname, modulename, arguments):
        apiindex, status, returnval, tid, timediff = context

        current_time = self.first_seen + datetime.timedelta(0,0, timediff*1000)
        timestring = logtime(current_time)

        self.lastcall = self._parse([timestring,
                                     tid,
                                     modulename,
                                     apiname, 
                                     status,
                                     returnval] + arguments)

    def _parse(self, row):
        """Parse log row.
        @param row: row data.
        @return: parsed information dict.
        """
        call = {}
        arguments = []

        try:
            timestamp = row[0]    # Timestamp of current API call invocation.
            thread_id = row[1]    # Thread ID.
            category = row[2]     # Win32 function category.
            api_name = row[3]     # Name of the Windows API.
            status_value = row[4] # Success or Failure?
            return_value = row[5] # Value returned by the function.
        except IndexError as e:
            log.debug("Unable to parse process log row: %s", e)
            return None

        # Now walk through the remaining columns, which will contain API
        # arguments.
        for index in range(6, len(row)):
            argument = {}

            # Split the argument name with its value based on the separator.
            try:                
                (arg_name, arg_value) = row[index]
            except ValueError as e:
                log.debug("Unable to parse analysis row argument (row=%s): %s", row[index], e)
                continue

            argument["name"] = arg_name
            argument["value"] = convert_to_printable(str(arg_value)).lstrip("\\??\\")
            arguments.append(argument)

        call["timestamp"] = timestamp
        call["thread_id"] = str(thread_id)
        call["category"] = category
        call["api"] = api_name
        call["status"] = bool(int(status_value))

        if isinstance(return_value, int):
            call["return"] = "0x%.08x" % return_value
        else:
            call["return"] = convert_to_printable(str(return_value))

        call["arguments"] = arguments
        call["repeated"] = 0

        return call

class Processes:
    """Processes analyzer."""

    def __init__(self, logs_path):
        """@param  logs_path: logs path."""
        self._logs_path = logs_path

    def run(self):
        """Run analysis.
        @return: processes infomartion list.
        """
        results = []

        if not os.path.exists(self._logs_path):
            log.error("Analysis results folder does not exist at path \"%s\".",
                      self._logs_path)
            return results

        if len(os.listdir(self._logs_path)) == 0:
            log.error("Analysis results folder does not contain any file.")
            return results

        for file_name in os.listdir(self._logs_path):
            file_path = os.path.join(self._logs_path, file_name)

            if os.path.isdir(file_path):
                continue
            
            if not file_path.endswith(".raw"):
                continue

            # Invoke parsing of current log file.
            current_log = ParseProcessLog(file_path)
            if current_log.process_id == None: continue

            # If the current log actually contains any data, add its data to
            # the global results list.
            results.append({
                "process_id": current_log.process_id,
                "process_name": current_log.process_name,
                "parent_id": current_log.parent_id,
                "first_seen": logtime(current_log.first_seen),
                "calls": current_log
            })

        # Sort the items in the results list chronologically. In this way we
        # can have a sequential order of spawned processes.
        results.sort(key=lambda process: process["first_seen"])

        return results

class Summary:
    """Generates summary information."""
    
    def __init__(self, proc_results):
        """@param oroc_results: enumerated processes results."""
        self.proc_results = proc_results

    def run(self):
        """Get registry keys, mutexes and files.
        @return: Summary of keys, mutexes and files.
        """
        keys = []
        mutexes = []
        files = []

        def _check_registry(handles, registry, subkey, handle):
            for known_handle in handles:
                if handle != 0 and handle == known_handle["handle"]:
                    return None

            name = ""
            if registry == 0x80000000:
                name = "HKEY_CLASSES_ROOT\\"
            elif registry == 0x80000001:
                name = "HKEY_CURRENT_USER\\"
            elif registry == 0x80000002:
                name = "HKEY_LOCAL_MACHINE\\"
            elif registry == 0x80000003:
                name = "HKEY_USERS\\"
            elif registry == 0x80000004:
                name = "HKEY_PERFORMANCE_DATA\\"
            elif registry == 0x80000005:
                name = "HKEY_CURRENT_CONFIG\\"
            elif registry == 0x80000006:
                name = "HKEY_DYN_DATA\\"
            else:
                for known_handle in handles:
                    if registry == known_handle["handle"]:
                        name = known_handle["name"] + "\\"

            handles.append({"handle" : handle, "name" : name + subkey})
            return name + subkey

        def _remove_handle(handles, handle):
            for known_handle in handles:
                if handle != 0 and handle == known_handle["handle"]:
                    handles.remove(known_handle)

        for process in self.proc_results:
            handles = []

            for call in process["calls"]:
                if call["api"].startswith("RegOpenKeyEx") or call["api"].startswith("RegCreateKeyEx"):
                    registry = 0
                    subkey = ""
                    handle = 0

                    for argument in call["arguments"]:
                        if argument["name"] == "Registry":
                            registry = int(argument["value"], 16)
                        elif argument["name"] == "SubKey":
                            subkey = argument["value"]
                        elif argument["name"] == "Handle":
                            handle = int(argument["value"], 16)

                    name = _check_registry(handles, registry, subkey, handle)
                    if name and name not in keys:
                        keys.append(name)
                elif call["api"].startswith("RegCloseKey"):
                    handle = 0

                    for argument in call["arguments"]:
                        if argument["name"] == "Handle":
                            handle = int(argument["value"], 16)
                    _remove_handle(handles, handle)

                elif call["category"] == "filesystem":
                    for argument in call["arguments"]:
                        if argument["name"] == "FileName":
                            value = argument["value"].strip()
                            if not value:
                                continue

                            if value not in files:
                                files.append(value)

                elif call["category"] == "synchronization":
                    for argument in call["arguments"]:
                        if argument["name"] == "MutexName":
                            value = argument["value"].strip()
                            if not value:
                                continue

                            if value not in mutexes:
                                mutexes.append(value)

        return {"files": files, "keys": keys, "mutexes": mutexes}

class ProcessTree:
    """Creates process tree."""

    def __init__(self, proc_results):
        """@param proc_results: enumerated processes information."""
        self.proc_results = proc_results
        self.processes = []
        self.proctree = []

    def gen_proclist(self):
        """Generate processes list.
        @return: True.
        """
        for entry in self.proc_results:
            process = {}
            process["name"] = entry["process_name"]
            process["pid"] = int(entry["process_id"])
            process["children"] = []
            
            for call in entry["calls"]:
                if call["api"] == "CreateProcessInternalW":
                    for argument in call["arguments"]:
                        if argument["name"] == "ProcessId":
                            process["children"].append(int(argument["value"]))

            self.processes.append(process)

        return True

    def add_node(self, node, parent_id, tree):
        """Add a node to a tree.
        @param node: node to add.
        @param parent_id: parent node.
        @param tree: processes tree.
        @return: boolean with operation success status.
        """
        for process in tree:
            if process["pid"] == parent_id:
                new = {}
                new["name"] = node["name"]
                new["pid"] = node["pid"]
                new["children"] = []
                process["children"].append(new)
                return True
            self.add_node(node, parent_id, process["children"])
            
        return False

    def populate(self, node):
        """Populate tree.
        @param node: node to add.
        @return: True.
        """
        for children in node["children"]:
            for proc in self.processes:
                if int(proc["pid"]) == int(children):
                    self.add_node(proc, node["pid"], self.proctree)
                    self.populate(proc)

        return True

    def run(self):
        """Run analysis.
        @return: results dict or None.
        """
        if not self.proc_results or len(self.proc_results) == 0:
            return None
    
        self.gen_proclist()
        root = {}
        root["name"] = self.processes[0]["name"]
        root["pid"] = self.processes[0]["pid"]
        root["children"] = []
        self.proctree.append(root)
        self.populate(self.processes[0])

        return self.proctree

class BehaviorAnalysis(Processing):
    """Behavior Analyzer."""

    def run(self):
        """Run analysis.
        @return: results dict.
        """
        self.key = "behavior"

        behavior = {}
        behavior["processes"]   = Processes(self.logs_path).run()
        behavior["processtree"] = ProcessTree(behavior["processes"]).run()
        behavior["summary"]     = Summary(behavior["processes"]).run()

        return behavior
