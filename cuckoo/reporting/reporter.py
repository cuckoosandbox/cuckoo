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
import sys
from string import split

from cuckoo.reporting.observers import AnalysisObservable
from cuckoo.reporting.config import ReportingConfig
from cuckoo.config.constants import CUCKOO_REPORTING_CONFIG_FILE

class ReportProcessor:
    """
    Handles reporting of analysis results.
    """

    def __init__(self, analysis_path):
        self._analysis_path = analysis_path
        self._observable = AnalysisObservable()

        # Load configuration
        if os.path.exists(CUCKOO_REPORTING_CONFIG_FILE):
            try:
                self.config = ReportingConfig(CUCKOO_REPORTING_CONFIG_FILE)
            except Exception, why:
                raise SystemExit
        else:
            raise SystemExit

        # Load modules
        self._tasklist()

    def report(self, report):
        """
        Takes care of a new report.
        @param report: an analysis report.
        """ 
        self._observable.notify(report)

    def _tasklist(self):
        """
        This is where reporting modules order comes true.
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
                self._observable.subscribe(imp.Report(self._analysis_path))
