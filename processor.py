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
import time
from datetime import datetime

from cuckoo.processing.config import AnalysisConfig
from cuckoo.processing.analysis import Analysis, ProcessTree
from cuckoo.processing.file import File
from cuckoo.processing.pcap import Pcap
from cuckoo.reporting.reporter import ReportProcessor

def get_analysis_duration(started):
    now = time.time()
    return int(now - started)

def main(analysis_path):
    if not os.path.exists(analysis_path):
        print "Analysis not found, check analysis path."
        return False

    config_path = os.path.join(analysis_path, "analysis.conf")

    config = AnalysisConfig(config_path)

    file_path = os.path.join(analysis_path, config.target)
    analysislog_path = os.path.join(analysis_path, "analysis.log")
    logs_path = os.path.join(analysis_path, "logs")
    dropped_path = os.path.join(analysis_path, "files")
    pcap_path = os.path.join(analysis_path, "dump.pcap")

    results = {}

    results["info"] = {}
    results["info"]["version"] = "0.2.1-dev"
    results["info"]["started"] = datetime.fromtimestamp(config.started).strftime("%Y-%m-%d %H:%M:%S")
    results["info"]["duration"] = "%d seconds" % get_analysis_duration(config.started)

    results["debug"] = {}
    results["debug"]["analysislog"] = open(analysislog_path, "rb").read()

    results["file"] = File(file_path).process()
    results["behavior"] = {}
    results["behavior"]["processes"] = Analysis(logs_path).process()
    results["behavior"]["processtree"] = ProcessTree(results["behavior"]["processes"]).process()
    results["network"] = Pcap(pcap_path).process()

    dropped_files = []
    for dropped in os.listdir(dropped_path):
        cur_path = os.path.join(dropped_path, dropped)
        cur_file = File(cur_path).process()
        dropped_files.append(cur_file)

    results["dropped"] = dropped_files

    if not results:
        return False

    if len(results) == 0:
        return False
  
    # Reports analysis to reports generation modules.
    ReportProcessor().report(results)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Not enough args."
        sys.exit(-1)

    main(sys.argv[1])

