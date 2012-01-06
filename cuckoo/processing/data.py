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
import time
import shutil
import base64
from datetime import datetime

from cuckoo.config.constants import VERSION
from cuckoo.processing.file import File
from cuckoo.processing.pcap import Pcap
from cuckoo.processing.config import AnalysisConfig
from cuckoo.processing.analysis import Analysis, ProcessTree

class CuckooDict:
    def __init__(self, analysis_path):
        self._analysis_path = analysis_path
        self._config_path   = os.path.join(analysis_path, "analysis.conf")
        self._log_path      = os.path.join(analysis_path, "analysis.log")
        self._pcap_path     = os.path.join(analysis_path, "dump.pcap")
        self._logs_path     = os.path.join(analysis_path, "logs")
        self._dropped_path  = os.path.join(analysis_path, "files")
        self._shots_path    = os.path.join(analysis_path, "shots")
        self._trace_path    = os.path.join(analysis_path, "trace")

    def _get_duration(self, started):
        """
        Calculates analysis duration.
        @param started: UNIX timestamp of the start time
        """
        now = time.time()
        return int(now - started)

    def _get_dropped(self):
        """
        Retrieves information on files dropped by the malware.
        @return: list with information on all dropped files
        """
        dropped = []

        if os.path.exists(self._dropped_path) and \
           len(os.listdir(self._dropped_path)) > 0:
            for cur_file in os.listdir(self._dropped_path):
                cur_path = os.path.join(self._dropped_path, cur_file)
                
                # Ignore ".gitignore" files.
                if cur_file == ".gitignore" and os.path.getsize(cur_path) == 0:
                    continue
                
                cur_info = File(cur_path).process()
                dropped.append(cur_info)

        return dropped
    
    def _get_screenshots(self):
        """
        Retrieves base64 encoded screenshots.
        @return: list with base64 encoded screenshots
        """
        screenshots = []

        shots_list = os.listdir(self._shots_path)
        
        if os.path.exists(self._shots_path) and len(shots_list) > 0:
            counter = 1
            for cur_shot in sorted(shots_list):
                cur_path = os.path.join(self._shots_path, cur_shot)

                if os.path.getsize(cur_path) == 0:
                    continue
                
                entry = {}
                entry["id"] = counter
                entry["data"] = base64.b64encode(open(cur_path, "rb").read())
                screenshots.append(entry)
                
                counter += 1
                
        screenshots.sort(key=lambda shot: shot["id"])
        
        return screenshots

    def process(self):
        """
        Process the analysis results and generate a dictionary containing all
        abstracted information.
        """
        if not os.path.exists(self._analysis_path):
            print "Analysis not found, check analysis path."
            return None

        config = AnalysisConfig(self._config_path)
        file_path = os.path.join(self._analysis_path, config.target)

        results = {}
        results["info"] = {}
        results["info"]["version"] = VERSION
        results["info"]["started"] = datetime.fromtimestamp(config.started).strftime("%Y-%m-%d %H:%M:%S")
        duration = self._get_duration(config.started)
        results["info"]["duration"] = "%d seconds" % duration
        results["info"]["ended"] = datetime.fromtimestamp(config.started+duration).strftime("%Y-%m-%d %H:%M:%S")

        results["debug"] = {}
        
        if os.path.exists(self._log_path) and os.path.getsize(self._log_path) > 0:
            debug_log = open(self._log_path, "rb").read()
        else:
            debug_log = "No analysis.log file found. Your analysis most likely failed to start."
        results["debug"]["log"] = debug_log

        results["file"] = File(file_path).process()
        results["static"] = {}
        results["dropped"] = self._get_dropped()
        results["screenshots"] = self._get_screenshots()
        results["network"] = Pcap(self._pcap_path).process()

        results["behavior"] = {}
        results["behavior"]["processes"] = Analysis(self._logs_path).process()
        results["behavior"]["processtree"] = ProcessTree(results["behavior"]["processes"]).process()

        if not results or len(results) == 0:
            return None

        return results
