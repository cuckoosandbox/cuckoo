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
import ConfigParser

from cuckoo.common.constants import CUCKOO_REPORTING_CONFIG_FILE

class ReportingConfig:
    """
    Reporting configuration parser
    """
    
    def __init__(self):
        """
        Creates a new reporting configuration
        @param config_path: path to reporting config file
        """ 
        if not os.path.exists(CUCKOO_REPORTING_CONFIG_FILE):
            raise SystemExit
        
        config = ConfigParser.ConfigParser()
        config.read(CUCKOO_REPORTING_CONFIG_FILE)
        
        self.enabled = {}

        for option in config.options('Tasks'):
            try:
                self.enabled[option] = config.getboolean('Tasks', option)
            except:
                self.enabled[option] = None
    
    def check(self, report):
        """
        Checks if a module is enabled from configuration
        @param task: report module
        @return: True or false
        """ 
        for module, status in self.enabled.items():
            if module.lower() == report:
                if status:
                    return True
        return False
