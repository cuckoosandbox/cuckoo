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
import json

from cuckoo.reporting.observers import BaseObserver

class Report(BaseObserver):
    """
    Save report in pure JSON format.
    """
    
    def update(self, results):
        report_path = os.path.join(sys.argv[1], "reports")
        if not os.path.exists(report_path):
            os.mkdir(report_path)
        
        try:
            report = open(os.path.join(report_path, "report.json"), "w")
            report.write(json.dumps(results, sort_keys = False, indent = 4))
            report.close()
        except Exception, e:
            print "Failed writing JSON report: %s" % e
