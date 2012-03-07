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
import pkgutil
from string import split

from cuckoo.reporting.observers import AnalysisObservable
from cuckoo.reporting.reportingconfig import ReportingConfig
import cuckoo.reporting.tasks as tasks

class ReportProcessor:
    """
    Handles reporting of analysis results.
    """

    def __init__(self, analysis_path):
        self._analysis_path = analysis_path
        self._observable = AnalysisObservable()
        self.config = ReportingConfig()

        # Load tasks.
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

        for loader, name, ispkg in pkgutil.iter_modules(tasks.__path__):
            if not self.config.check(name):
                continue

            path = "%s.%s" % (tasks.__name__, name)
            task = __import__(path,
                              globals(),
                              locals(),
                              ['Report'],
                              -1)

            report = task.Report(self._analysis_path)
            report.setOptions(self.config.get(name))
            self._observable.subscribe(report)
