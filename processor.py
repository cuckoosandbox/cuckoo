#!/usr/bin/env python
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
import logging
from optparse import OptionParser

from cuckoo.processing.cuckoodict import CuckooDict
from cuckoo.reporting.reporter import ReportProcessor
from cuckoo.common.crash import crash

def init_logging(analysis_path = None):
    root = logging.getLogger()
    formatter = logging.Formatter('[%(asctime)s] [%(name)s] %(levelname)s: %(message)s')
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    root.addHandler(stream_handler)
    
    if analysis_path:
        if os.path.exists(analysis_path):
            file_handler = logging.FileHandler(os.path.join(analysis_path, "processor.log"))
            file_handler.setFormatter(formatter)
            root.addHandler(file_handler)
    
    root.setLevel(logging.DEBUG)
    
    return True

def main():
    analysis_path = None
    log = logging.getLogger("Processor")

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

    init_logging(analysis_path)
    log.info("Post-analysis processing started.")
    
    if not analysis_path:
        log.warning("No analysis results path specified.")
    elif not os.path.exists(analysis_path):
        log.error("The analysis results folder at path \"%s\" does not exist." % analysis_path)
    else:
        log.info("Starting processing of results at path \"%s\"." % analysis_path)

    if options.message:
        print options.message

    if options.custom:
        print options.custom

    if analysis_path:
        # Generate reports out of abstracted analysis results.
        ReportProcessor(analysis_path).report(CuckooDict(analysis_path).process())
    
    log.info("Post-analysis processing completed.")

    return True

if __name__ == "__main__": 
    try:
        main()
    except KeyboardInterrupt:
        pass
    except SystemExit:
        pass
    except:
        crash()
