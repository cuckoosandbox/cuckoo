# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import csv
import logging

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.utils import convert_to_printable

log = logging.getLogger(__name__)

class ParseProcessLog:
    """Parses process log file."""
    
    def __init__(self, log_path):
        """@param log_path: log file path."""
        self._log_path = log_path
        self.process_id = None
        self.process_name = None
        self.parent_id = None
        self.process_first_seen = None
        self.calls = []

    def _parse(self, row):
        """Parse log row.
        @param row: row data.
        @return: parsed information dict.
        """
        call = {}
        arguments = []

        try:
            timestamp = row[0]    # Timestamp of current API call invocation.
            process_id = row[1]   # ID of the process that performed the call.
            process_name = row[2] # Name of the process.
            parent_id = row[3]    # PID of the parent process
            category = row[4]     # Win32 function category
            api_name = row[5]     # Name of the Windows API.
            status_value = row[6] # Success or Failure?
            return_value = row[7] # Value returned by the function.
        except IndexError as e:
            log.warning("Unable to parse analysis log row: %s" % e.message)
            return False

        if not self.process_id:
            self.process_id = process_id

        if not self.process_name:
            self.process_name = process_name
            
        if not self.parent_id:
            self.parent_id = parent_id

        if not self.process_first_seen:
            self.process_first_seen = timestamp

        # Now walk through the remaining columns, which will contain API
        # arguments.
        for index in range(8, len(row)):
            argument = {}

            # Split the argument name with its value based on the separator.
            try:                
                (arg_name, arg_value) = row[index].split("->")
            except ValueError as e:
                print row[index]
                log.warning("Unable to parse analysis row argument: %s" % e.message)
                continue

            argument["name"] = arg_name
            argument["value"] = convert_to_printable(arg_value)
            arguments.append(argument)

        call["timestamp"] = timestamp
        call["category"] = category
        call["api"] = api_name
        call["status"] = status_value
        call["return"] = convert_to_printable(return_value)
        call["arguments"] = arguments
        call["repeated"] = 0

        # Check if the current API call is a repetition of the previous one.
        if len(self.calls) > 0:
            if self.calls[-1]["api"] == call["api"] and \
               self.calls[-1]["status"] == call["status"] and \
               self.calls[-1]["arguments"] == call["arguments"] and \
               self.calls[-1]["return"] == call["return"]:
                self.calls[-1]["repeated"] += 1
                return True

        self.calls.append(call)

        return True

    def extract(self):
        """Get data from CSV file.
        @return: boolean with status of parsing process.
        """
        if not os.path.exists(self._log_path):
            log.error("Analysis logs folder does not exist at path \"%s\"."
                      % self._log_path)
            return False

        reader = csv.reader(open(self._log_path, "rb"))

        try:
            for row in reader:
                self._parse(row)
        except csv.Error as e:
            log.warning("Something went wrong while parsing analysis log: %s"
                        % e.message)

        return True

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
            log.error("Analysis results folder does not exist at path \"%s\"."
                      % self._logs_path)
            return results

        if len(os.listdir(self._logs_path)) == 0:
            log.error("Analysis results folder does not contain any file.")
            return results

        for file_name in os.listdir(self._logs_path):
            file_path = os.path.join(self._logs_path, file_name)

            if os.path.isdir(file_path):
                continue

            # Invoke parsing of current log file.
            current_log = ParseProcessLog(file_path)
            current_log.extract()

            # If the current log actually contains any data, add its data to
            # the global results list.
            if len(current_log.calls) > 0:
                process = {}
                process["process_id"]   = current_log.process_id
                process["process_name"] = current_log.process_name
                process["parent_id"]    = current_log.parent_id
                process["first_seen"]   = current_log.process_first_seen
                process["calls"]        = current_log.calls

                results.append(process)

        # Sort the items in the results list chronologically. In this way we
        # can have a sequential order of spawned processes.
        results.sort(key=lambda process: process["first_seen"])

        return results

class Summary:
    """Generates summary information."""
    
    def __init__(self, proc_results):
        """@param oroc_results: enumerated processes results."""
        self.proc_results = proc_results

    def _gen_files(self):
        """Gets files calls.
        @return: information list.
        """
        files = []

        for entry in self.proc_results:
            for call in entry["calls"]:
                if call["category"] == "filesystem":
                    for argument in call["arguments"]:
                        if argument["name"] == "lpFileName":
                            if argument["value"] not in files:
                                files.append(argument["value"])

        return files

    def _gen_keys(self):
        """Get registry calls.
        @return: keys information list.
        """
        keys = []

        for entry in self.proc_results:
            for call in entry["calls"]:
                if call["category"] == "registry":
                    hKey = None
                    lpSubKey = None
                    for argument in call["arguments"]:
                        if argument["name"] == "hKey":
                            hKey = argument["value"]
                        elif argument["name"] == "lpSubKey":
                            lpSubKey = argument["value"]

                    if lpSubKey:
                        key = "%s\\\\%s" % (hKey, lpSubKey)
                        if key not in keys:
                            keys.append(key)

        return keys

    def _gen_mutexes(self):
        """Get mutexes information.
        @return: Mutexes information list.
        """
        mutexes = []

        for entry in self.proc_results:
            for call in entry["calls"]:
                if call["category"] == "synchronization":
                    for argument in call["arguments"]:
                        if argument["name"] == "lpName":
                            if argument["value"] not in mutexes:
                                mutexes.append(argument["value"])

        return mutexes

    def run(self):
        """Run analysis.
        @return: information dict.
        """
        summary = {}
        summary["files"] = self._gen_files()
        summary["keys"] = self._gen_keys()
        summary["mutexes"] = self._gen_mutexes()

        return summary

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
                if call["api"] == "CreateProcessA" or \
                   call["api"] == "CreateProcessW":
                    if call["return"].strip() != "":
                        process["children"].append(int(call["return"].strip()))
                    
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
