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
from ctypes import *

sys.path.append("\\\\VBOXSVR\\setup\\lib\\")

import cuckoo.defines
from cuckoo.logging import *
from cuckoo.paths import *
from cuckoo.inject import *

def cuckoo_resumethread(h_thread = -1):
    cuckoo.defines.KERNEL32.Sleep(2000)
    # If the resume fails we need to abort the analysis, as there won't be
    # any activity monitored.
    if not cuckoo.defines.KERNEL32.ResumeThread(h_thread):
        log("Unable to resume thread with handle \"0x%08x\" (GLE=%s)."
            % (h_thread, cuckoo.defines.KERNEL32.GetLastError()), "ERROR")
        return False
    else:
        log("Resumed thread with handle \"0x%08x\"." % h_thread, "INFO")

    return True

def cuckoo_monitor(pid = -1, h_thread = -1, suspended = False, dll_path = None):
    # The package run function should return the process id, if it's valid
    # I can inject it with Cuckoo's DLL or specified custom DLL.
    if pid > -1:
        # If injection fails I have to abort execution as there won't be
        # anything monitored.
        if not dll_path or dll_path == CUCKOO_DLL_PATH:
            dll_path = CUCKOO_DLL_PATH
            log("Using default Cuckoo DLL \"%s\"." % dll_path, "INFO")
        else:
            log("Using custom DLL \"%s\"." % dll_path, "INFO")

        if not cuckoo_inject(pid, dll_path):
            log("Unable to inject process with ID \"%d\" with DLL \"%s\"" \
                " (GLE=%s)." % (pid, dll_path, cuckoo.defines.KERNEL32.GetLastError()),
                "ERROR")
            return False
        else:
            log("Original process with ID \"%d\"successfully injected." % pid)

    # In case the process was create in suspended mode and needs to be resumed,
    # I'll do it now.
    if suspended and h_thread > -1:
        if not cuckoo_resumethread(h_thread):
            return False

    return True
