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
import shutil
from datetime import datetime

from cuckoo.processing.config import AnalysisConfig
from cuckoo.processing.analysis import Analysis, ProcessTree
from cuckoo.processing.file import File
from cuckoo.processing.pcap import Pcap
from cuckoo.reporting.reporter import ReportProcessor

def get_analysis_duration(started):
    """
    Calculate analysis duration.
    @param started: UNIX timestamp of the start time
    """
    now = time.time()
    return int(now - started)

def get_dropped_files(dropped_path):
    """
    Retrieve information on files dropped by the malware.
    @param dropped_path: path to the dropped files dumps
    """
    dropped_files = []

    if os.path.exists(dropped_path) and len(os.listdir(dropped_path)) > 0:
        for dropped in os.listdir(dropped_path):
            cur_path = os.path.join(dropped_path, dropped)
            cur_file = File(cur_path).process()
            dropped_files.append(cur_file)

    return dropped_files

def move_pcap(analysis_path):
    """
    Create a new folder and move the PCAP file in it.
    @param analysis_path: path to current analysis results directory
    """
    pcap_file_path = os.path.join(analysis_path, "dump.pcap")
    pcap_dir_path = os.path.join(analysis_path, "pcap/")

    if os.path.exists(pcap_file_path):
        if not os.path.exists(pcap_dir_path):
            try:
                os.mkdir(pcap_dir_path)
            except OSError, why:
                return False

        try:
            shutil.move(pcap_file_path, pcap_dir_path)
        except IOError, why:
            return False
    else:
        return False

    return True

def main(analysis_path):
    """
    Process the analysis results and generate reports.
    @param analysis_path: path to the analysis results folder
    """
    if not os.path.exists(analysis_path):
        print "Analysis not found, check analysis path."
        return False

    config_path = os.path.join(analysis_path, "analysis.conf")
    config = AnalysisConfig(config_path)

    file_path    = os.path.join(analysis_path, config.target)
    log_path     = os.path.join(analysis_path, "analysis.log")
    logs_path    = os.path.join(analysis_path, "logs")
    dropped_path = os.path.join(analysis_path, "files")
    shots_path   = os.path.join(analysis_path, "shots")
    trace_path   = os.path.join(analysis_path, "trace")
    pcap_path    = os.path.join(analysis_path, "dump.pcap")

    results = {}

    results["info"] = {}
    results["info"]["version"] = "0.2.1-dev"
    results["info"]["started"] = datetime.fromtimestamp(config.started).strftime("%Y-%m-%d %H:%M:%S")
    results["info"]["duration"] = "%d seconds" % get_analysis_duration(config.started)

    results["debug"] = {}
    results["debug"]["log"] = open(log_path, "rb").read()

    results["file"] = File(file_path).process()
    results["dropped"] = get_dropped_files(dropped_path)
    results["network"] = Pcap(pcap_path).process()

    results["behavior"] = {}
    results["behavior"]["processes"] = Analysis(logs_path).process()
    results["behavior"]["processtree"] = ProcessTree(results["behavior"]["processes"]).process()

    if not results or len(results) == 0:
        return False
  
    # Reports analysis to reports generation modules.
    ReportProcessor().report(results)

    move_pcap(analysis_path)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Not enough args."
        sys.exit(-1)

    main(sys.argv[1])
