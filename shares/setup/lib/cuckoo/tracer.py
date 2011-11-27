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
import logging

log = logging.getLogger("Tracer")

try:
    from cuckoo.debugger import *
    IS_DEBUGGER = True
except ImportError, why:
    log.error("Unable to import debugger functions: %s" % why)
    IS_DEBUGGER = False

def cuckoo_trace(pid = -1):
    log = logging.getLogger("Tracer.Start")

    # If WinAppDbg is installed I just abort execution of this function, in
    # order to keep it as an optional dependency.
    if not IS_DEBUGGER:
        return False

    if pid > -1:
        log.info("Starting instruction tracing for process with ID \"%d\"."
                 % pid)
        tracer = TraceInstructions(pid)
        tracer.daemon = True
        tracer.start()

        return True
