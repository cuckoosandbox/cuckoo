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

class BaseObserver:
    """
    Base observer class to be inherited by post-processor modules.
    """
    
    def __init__(self, analysis_path):
        self._analysis_path = analysis_path
        self._checkReportDir()
        
    def _checkReportDir(self):
        """
        Checks if reports directorys exists, otherwise create it.
        """
        self.report_path = os.path.join(self._analysis_path, "reports")
        if not os.path.exists(self.report_path):
            os.mkdir(self.report_path)
    
    def update(self):
        """
        Called when a new event must be notified to observers. You have to implement it.
        @raise NotImplementError: if not implemented in reporting module.
        """
        raise NotImplementError
    
class AnalysisObservable:
    """
    Analysis observable, gets the analysis and notifies subscribed observers.
    """
    
    def __init__(self):
        self._observers = []
        
    def subscribe(self, observer):
        """
        Subscribe a observer to analysis notification service.
        @param observer: a BaseObserver instance. 
        """
        assert isinstance(observer, BaseObserver)
        self._observers.append(observer)    
        
    def notify(self, results):
        """
        Notifies all observer. 
        @param results: results to pass to observers.
        """ 
        for observer in self._observers:
            observer.update(results)
