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

from datetime import datetime

from cuckoo.common.file import File
from cuckoo.common.analysisconfig import AnalysisConfig
from cuckoo.common.constants import CUCKOO_VERSION
from cuckoo.processing.observers import Analysis

class InfoAnalysis(Analysis):
    def process(self):
        self.key = "info"

        config = AnalysisConfig(self._config_path)

        info = {}
        info["version"]  = CUCKOO_VERSION
        info["started"]  = datetime.fromtimestamp(config.started).strftime("%Y-%m-%d %H:%M:%S")
        info["duration"] = "%d seconds" % (config.completed - config.started)
        info["ended"]    = datetime.fromtimestamp(config.completed).strftime("%Y-%m-%d %H:%M:%S")

        return info
