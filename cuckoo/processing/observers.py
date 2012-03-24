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

from cuckoo.common.analysisconfig import AnalysisConfig

class Analysis(object):
    def __init__(self, analysis_path = None):
        if not analysis_path:
            return

        self.key                = ""
        self._analysis_path     = analysis_path
        self._config_path       = os.path.join(analysis_path, "analysis.conf")
        self._analysis_log_path = os.path.join(analysis_path, "analysis.log")
        self._pcap_path         = os.path.join(analysis_path, "dump.pcap")
        self._logs_path         = os.path.join(analysis_path, "logs")
        self._dropped_path      = os.path.join(analysis_path, "files")
        self._shots_path        = os.path.join(analysis_path, "shots")
        self._additional_path   = os.path.join(analysis_path, "additional")

        config = AnalysisConfig(self._config_path)

        self._file_path         = os.path.join(analysis_path, config.target)

    def process(self):
        raise NotImplementedError

class Signature(object):
    def __init__(self):
        self.name        = ""
        self.description = ""
        self.severity    = 0
        self.alert       = False
        self.enabled     = True

    def process(self, results = None):
        raise NotImplementedError
