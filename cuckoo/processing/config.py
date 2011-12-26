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

import ConfigParser

class AnalysisConfig:
    """
    Analysis configuration storage
    """
    
    def __init__(self, config_path):
        """
        Creates a new analysis configuration
        @param config_path: path to analysis config file
        """ 
        config = ConfigParser.ConfigParser()
        config.read(config_path)
        self.target = config.get("analysis", "target")
        self.package = config.get("analysis", "package")
        self.timeout = config.get("analysis", "timeout")
        self.share = config.get("analysis", "share")
        self.started = float(config.get("analysis", "started"))
        self.custom = config.get("analysis", "custom")
