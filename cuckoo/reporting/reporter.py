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


from cuckoo.reporting.observers import AnalysisObservable

class ReportProcessor:
    """
    Handles reporting of analysis results.
    """
    
    def __init__(self):
        self._observable = AnalysisObservable()
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
        from cuckoo.reporting.tasks.jsondump import JsonDump
        self._observable.subscribe(JsonDump())
        from cuckoo.reporting.tasks.reporttxt import ReportTxt
        self._observable.subscribe(ReportTxt())
        from cuckoo.reporting.tasks.reporthtml import ReportHTML
        self._observable.subscribe(ReportHTML())

