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

import sys

from cuckoo.processing.data import CuckooDict
from cuckoo.reporting.reporter import ReportProcessor

def main(analysis_path):
    # Generate reports out of abstracted analysis results.
    ReportProcessor().report(CuckooDict(analysis_path).process())

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Not enough args."
        sys.exit(-1)

    main(sys.argv[1])
