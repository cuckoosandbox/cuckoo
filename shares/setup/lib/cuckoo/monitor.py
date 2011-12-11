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

sys.path.append("\\\\VBOXSVR\\setup\\lib\\")

import cuckoo.defines
from cuckoo.paths import *
from cuckoo.inject import *

def cuckoo_resumethread(h_thread = -1):
    """
    Resumes the thread of a process created in suspended mode.
    @param h_thread: handle to the thread to resume
    """

    log = logging.getLogger("Monitor.ResumeThread")

    cuckoo.defines.KERNEL32.Sleep(2000)
    # If the resume fails we need to abort the analysis, as there won't be
    # any activity monitored.
    if not cuckoo.defines.KERNEL32.ResumeThread(h_thread):
        log.error("Unable to resume thread with handle \"0x%08x\" (GLE=%d)."
                  % (h_thread, cuckoo.defines.KERNEL32.GetLastError()))
        return False
    else:
        log.info("Resumed thread with handle \"0x%08x\"." % h_thread)

    return True

def cuckoo_monitor(pid = -1, h_thread = -1, suspended = False, dll_path = None):
    """
    Invokes injection and resume of the specified process.
    @param pid: PID of the process to monitor
    @param h_thread: handle of the thread of the process to monitor
    @param suspended: boolean value enabling or disabling the resume of the
                      specified process from suspended mode
    @param dll_path: path to the DLL to inject, if none is specified it will use
                     the default DLL
    """

    log = logging.getLogger("Monitor.Monitor")

    # The package run function should return the process id, if it's valid
    # I can inject it with Cuckoo's DLL or specified custom DLL.
    if pid > -1:
        if not dll_path or dll_path == CUCKOO_DLL_PATH:
            dll_path = CUCKOO_DLL_PATH
            log.info("Using default Cuckoo DLL \"%s\"." % dll_path)
        else:
            log.info("Using custom DLL \"%s\"." % dll_path)

        if not cuckoo_inject(pid, dll_path):
            log.error("Unable to inject process with ID \"%d\" with DLL " \
                      "\"%s\" (GLE=%s)."
                      % (pid, dll_path, cuckoo.defines.KERNEL32.GetLastError()))
            return False
        else:
            log.info("Original process with PID \"%d\" successfully injected."
                     % pid)

    # Resume the process in case it was created in suspended mode.
    if suspended and h_thread > -1:
        if not cuckoo_resumethread(h_thread):
            return False

    return True
