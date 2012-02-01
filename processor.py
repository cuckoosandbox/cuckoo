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

import sys
from optparse import OptionParser

from cuckoo.processing.data import CuckooDict
from cuckoo.reporting.reporter import ReportProcessor
from cuckoo.logging.crash import crash

def main():
    analysis_path = None

    parser = OptionParser(usage="usage: %prog [options] analysispath")
    parser.add_option("-m", "--message",
                      action="store",
                      type="string",
                      dest="message",
                      default=None,
                      help="Specify a message to notify to the processor script")
    parser.add_option("-c", "--custom",
                      action="store",
                      type="string",
                      dest="custom",
                      default=None,
                      help="Specify a custom value to be used by the processor")

    (options, args) = parser.parse_args()

    if len(args) == 1:
        try:
            analysis_path = args[0]
        except IndexError, why:
            pass

    if options.message:
        print options.message

    if options.custom:
        print options.custom

    if analysis_path:
        # Generate reports out of abstracted analysis results.
        ReportProcessor(analysis_path).report(CuckooDict(analysis_path).process())

    return True

if __name__ == "__main__": 
    try:
        main()
    except KeyboardInterrupt:
        print "User aborted."
    except SystemExit:
        pass
    except:
        crash()

