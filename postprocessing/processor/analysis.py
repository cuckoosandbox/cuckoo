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

from processor.analysislog import AnalysisLog

class Analysis:
    def __init__(self, logs_path):
        self._logs_path = logs_path

    def process(self):
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
            current_log = AnalysisLog(file_path)
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
