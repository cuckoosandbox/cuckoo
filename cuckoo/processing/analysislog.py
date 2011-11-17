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

class AnalysisLog:
    def __init__(self, log_path):
        self._log_path = log_path
        self.process_id         = None
        self.process_name       = None
        self.process_first_seen = None
        self.calls = []

    def _encode(self, string):
        try:
            u_string = unicode(string, "utf-8", errors="replace")
            return u_string.encode("utf-8")
        except Exception, why:
            return ""

    def _parse(self, row):
        call = {}
        arguments = []

        # Try to acquire the first fixed columns.
        try:
            timestamp    = row[0]   # Timestamp of current API call invocation.
            process_id   = row[1]   # PID of the process which performed it.
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
            argument["value"] = self._encode(arg_value)

            # Add the current argument to the complete arguments list.
            arguments.append(argument)

        call["timestamp"] = timestamp
        call["api"]       = api_name
        call["status"]    = status_value
        call["return"]    = self._encode(return_value)
        call["arguments"] = arguments
        call["repeated"]  = 0

        # Check if the current API call is a repetition of the previous one.
        if len(self.calls) > 0:
            if self.calls[-1]["api"] == call["api"] and self.calls[-1]["status"] == call["status"] and self.calls[-1]["arguments"] == call["arguments"] and self.calls[-1]["return"] == call["return"]:
                self.calls[-1]["repeated"] += 1
                return True

        # If it's a new one, add it to the list.
        self.calls.append(call)

        return True

    def extract(self):
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
