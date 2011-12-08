#!/usr/bin/python
# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2011  Claudio "nex" Guarnieri (nex@cuckoobox.org)
# http://www.cuckoobox.org
#
# This file is part of Cuckoo.
#
# Cuckoo is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Cuckoo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.

import os
import sys
import csv
import string

class ParseLog:
    """
    Parses the specified process log file.
    """
    def __init__(self, log_path):
        self._log_path = log_path
        self.process_id         = None
        self.process_name       = None
        self.process_first_seen = None
        self.calls = []

    def _convert_char(self, char):
        """
        Converts a character in a printable format.
        @return: printable character
        """
        if char in string.ascii_letters or \
           char in string.digits or \
           char in string.punctuation or \
           char in string.whitespace:
            return char
        else:
            return r'\x%02x' % ord(char)

    def _convert_to_printable(self, s):
        """
        Converts a string in a printable format.
        @return: printable string
        """
        return ''.join([self._convert_char(c) for c in s])

    def _parse(self, row):
        """
        Parses a CSV row from the log file.
        """
        call = {}
        arguments = []

        # Try to acquire the first fixed columns.
        try:
            timestamp    = row[0]   # Timestamp of current API call invocation.
            process_id   = row[1]   # ID of the process that performed the call.
            process_name = row[2]   # Name of the process.
            api_name     = row[3]   # Name of the Windows API.
            status_value = row[4]   # Success or Failure?
            return_value = row[5]   # Value returned by the function.
        except IndexError, why:
            return False

        if not self.process_id:
            self.process_id = process_id

        if not self.process_name:
            self.process_name = process_name

        if not self.process_first_seen:
            self.process_first_seen = timestamp

        # Now walk through the remaining columns, which will contain API
        # arguments.
        for index in range(6, len(row)):
            argument = {}

            # Split the argument name with its value based on the separator.
            try:                
                (arg_name, arg_value) = row[index].split("->")
            except ValueError, why:
                continue

            argument["name"]  = arg_name
            argument["value"] = self._convert_to_printable(arg_value)

            # Add the current argument to the complete arguments list.
            arguments.append(argument)

        call["timestamp"] = timestamp
        call["api"]       = api_name
        call["status"]    = status_value
        call["return"]    = self._convert_to_printable(return_value)
        call["arguments"] = arguments
        call["repeated"]  = 0

        # Check if the current API call is a repetition of the previous one.
        if len(self.calls) > 0:
            if self.calls[-1]["api"] == call["api"] and \
               self.calls[-1]["status"] == call["status"] and \
               self.calls[-1]["arguments"] == call["arguments"] and \
               self.calls[-1]["return"] == call["return"]:
                self.calls[-1]["repeated"] += 1
                return True

        # If it's a new one, add it to the list.
        self.calls.append(call)

        return True

    def extract(self):
        """
        Processes the specified process log file.
        """
        if not os.path.exists(self._log_path):
            return False

        # Open current file with the CSV reader.
        reader = csv.reader(open(self._log_path, "rb"))

        # Walk to all file's rows and parse them.
        try:
            for row in reader:
                self._parse(row)
        except csv.Error, why:
            pass

        return True

class Analysis:
    """
    Processes all the results from the specified analysis.
    """
    def __init__(self, logs_path):
        self._logs_path = logs_path

    def process(self):
        """
        Processes all the files from the specified analysis results path.
        @return: dictionary containing the abstracted analysis results
        """
        results = []

        # Check if the specified directory exists.
        if not os.path.exists(self._logs_path):
            return False

        # Check if the specified directory contains any file.
        if len(os.listdir(self._logs_path)) == 0:
            return False

        # Walk through all the files.
        for file_name in os.listdir(self._logs_path):
            file_path = os.path.join(self._logs_path, file_name)

            # Skip if it is a directory.
            if os.path.isdir(file_path):
                continue

            # Invoke parsing of current log file.
            current_log = ParseLog(file_path)
            current_log.extract()

            # If the current log actually contains any data, add its data to
            # the global results list.
            if len(current_log.calls) > 0:
                process = {}
                process["process_id"]   = current_log.process_id
                process["process_name"] = current_log.process_name
                process["first_seen"]   = current_log.process_first_seen
                process["calls"]        = current_log.calls

                results.append(process)

        # Sort the items in the results list chronologically. In this way we
        # can have a sequential order of spawned processes.
        results.sort(key=lambda process: process["first_seen"])

        return results

class ProcessTree:
    """
    Generates a hyerarhical process tree.
    """
    def __init__(self, proc_results):
        self.proc_results = proc_results
        self.processes = []
        self.proctree = []

    def gen_proclist(self):
        """
        Generates the list of processes involved in the analysis.
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
        """
        Adds a node to the tree.
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
        """
        Populates the tree.
        """
        for children in node["children"]:
            for proc in self.processes:
                if int(proc["pid"]) == int(children):
                    self.add_node(proc, node["pid"], self.proctree)
                    self.populate(proc)

        return True

    def process(self):
        """
        Invokes the tree population.
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
