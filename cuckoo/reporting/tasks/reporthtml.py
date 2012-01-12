#!/usr/bin/python
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

from cuckoo.reporting.observers import BaseObserver

try:
    from mako.template import Template
    from mako.lookup import TemplateLookup
    IS_MAKO = True
except ImportError, why:
    IS_MAKO = False

class Report(BaseObserver):
    """
    Generates a human readable HTML report.
    """

    def update(self, results):
        if not IS_MAKO:
            return False

        report_path = os.path.join(sys.argv[1], "reports")
        if not os.path.exists(report_path):
            os.mkdir(report_path)

        lookup = TemplateLookup(directories=["cuckoo/web/"],
                                output_encoding='utf-8',
                                encoding_errors='replace')
        
        template = lookup.get_template("report.html")
        html = template.render(**results)
        
        try:
            report = open(os.path.join(report_path, "report.html"), "w")
            report.write(html)
            report.close()
        except Exception, e:
            print "Failed writing HTML report: %s" % e

        return True
