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
import sys
import logging
from ctypes import *

sys.path.append("\\\\VBOXSVR\\setup\\lib")

import cuckoo.defines

def check_process(pid):
    log = logging.getLogger("CheckProcess.CheckProcess")
    h_process = cuckoo.defines.KERNEL32.OpenProcess(cuckoo.defines.PROCESS_ALL_ACCESS,
                                                    False,
                                                    int(pid))

    if not h_process:
        log.error("Unable to open handle on process with PID %d (GLE=%d)."
                  % (pid, cuckoo.defines.KERNEL32.GetLastError()))
        return False

    exit_code = c_ulong(0)
    cuckoo.defines.KERNEL32.GetExitCodeProcess(h_process,
                                               byref(exit_code))

    if exit_code.value == cuckoo.defines.STILL_ACTIVE:
        return True
    else:
        return False
