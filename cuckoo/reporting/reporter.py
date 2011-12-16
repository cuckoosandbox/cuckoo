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
from string import split

from cuckoo.reporting.observers import AnalysisObservable
from cuckoo.reporting.config import ReportingConfig
from cuckoo.logging.colors import *
from cuckoo.config.costants import *

class ReportProcessor:
    """
    Handles reporting of analysis results.
    """
    
    def __init__(self):
        self._observable = AnalysisObservable()
        # Loaf configuration
        if os.path.exists(REPORTING_CONF_FILE):
            try:
                self.config = ReportingConfig(REPORTING_CONF_FILE)
            except Exception, why:
                print(red("[Config] [ERROR] Cannot read config file \"%s\": %s."
                          % (REPORTING_CONF_FILE, why)))
                sys.exit(-1)
        else:
            print(red("[Config] [ERROR] Cannot find config file \"%s\"."
                      % REPORTING_CONF_FILE))
            sys.exit(-1)
        
        # Load modules
        self._tasklist()
    
    def report(self, report):
        """
        Take in care a new report.
        @param report: an analysis report.
        """ 
        self._observable.notify(report)

    def _tasklist(self):
        """
        This is where reporting modules order become true.
        @note: if you add a reporting module you have to edit this.
        """
        for file in [tga for tga in os.listdir(os.path.join('.', "cuckoo/reporting/tasks")) if tga.endswith(".py")]:
            # Skip package file
            if file == '__init__.py':
                continue
            
            # Check if reporting module is enabled
            report = split(file, '.')[0]
            if self.config.check(report):           
                # Import reporting class
                module = "cuckoo.reporting.tasks.%s" % report
                imp = __import__(module, globals(), locals(), ['Report'], -1)
                
                # Subscribe
                self._observable.subscribe(imp.Report())
