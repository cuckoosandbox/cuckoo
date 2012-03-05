# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2012  Claudio "nex" Guarnieri (nex@cuckoobox.org)
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
import re
import sys
import time
import shutil
import base64
import logging
from datetime import datetime

from cuckoo.common.constants import CUCKOO_VERSION
from cuckoo.processing.file import File
from cuckoo.processing.pcap import Pcap
from cuckoo.processing.analysisconfig import AnalysisConfig
from cuckoo.processing.pe import PortableExecutable
from cuckoo.processing.analysis import BehaviorAnalysis, BehaviorSummary, ProcessTree
from cuckoo.processing.signatures import SignaturesProcessor

class CuckooDict:
    def __init__(self, analysis_path):
        self._analysis_path      = analysis_path
        self._config_path        = os.path.join(analysis_path, "analysis.conf")
        self._log_path           = os.path.join(analysis_path, "analysis.log")
        self._pcap_path          = os.path.join(analysis_path, "dump.pcap")
        self._logs_path          = os.path.join(analysis_path, "logs")
        self._dropped_path       = os.path.join(analysis_path, "files")
        self._shots_path         = os.path.join(analysis_path, "shots")
        self._additional_path    = os.path.join(analysis_path, "additional")

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

        if not os.path.exists(self._shots_path):
            return screenshots

        shots_list = os.listdir(self._shots_path)
        
        if len(shots_list) > 0:
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
        log = logging.getLogger("Processing.CuckooDict")
        
        if not os.path.exists(self._analysis_path):
            log.error("Analysis results folder does not exist at path \"%s\"."
                      % self._analysis_path)
            return None

        config = AnalysisConfig(self._config_path)
        file_path = os.path.join(self._analysis_path, config.target)

        # This is the root dictionary.
        results = {}
        
        results["info"] = {}
        results["info"]["version"] = CUCKOO_VERSION
        results["info"]["started"] = datetime.fromtimestamp(config.started).strftime("%Y-%m-%d %H:%M:%S")
        results["info"]["duration"] = "%d seconds" % (config.completed - config.started)
        results["info"]["ended"] = datetime.fromtimestamp(config.completed).strftime("%Y-%m-%d %H:%M:%S")

        results["debug"] = {}
        
        if os.path.exists(self._log_path) and os.path.getsize(self._log_path) > 0:
            results["debug"]["log"] = open(self._log_path, "rb").read()
        else:
            results["debug"]["log"] = "No analysis.log file found. Your analysis most likely failed to start."

        results["file"] = File(file_path).process()

        results["static"] = {}
        if "type" in results["file"]:
            if results["file"]["type"] and results["file"]["type"] != "":
                if re.search("PE32", results["file"]["type"]):
                    results["static"] = PortableExecutable(file_path).process()

        results["dropped"] = self._get_dropped()
        #results["screenshots"] = self._get_screenshots()
        results["network"] = Pcap(self._pcap_path).process()

        results["behavior"] = {}
        results["behavior"]["processes"] = BehaviorAnalysis(self._logs_path).process()
        results["behavior"]["processtree"] = ProcessTree(results["behavior"]["processes"]).process()
        results["behavior"]["summary"] = BehaviorSummary(results["behavior"]["processes"]).process()
        
        results["signatures"] = SignaturesProcessor().process(results)

        if not results or len(results) == 0:
            return None

        return results
