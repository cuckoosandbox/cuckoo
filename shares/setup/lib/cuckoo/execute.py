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

from cuckoo.defines import *
from cuckoo.logging import *

def cuckoo_execute(target_path, args = None, suspend = False):
    if not os.path.exists(target_path):
        log("Unable to create process \"%s\": file does not exist.", "ERROR")
        return (-1, -1)

    startupinfo = STARTUPINFO()
    startupinfo.cb = sizeof(startupinfo)
    process_information = PROCESS_INFORMATION()

    if args:
        arguments = "\"" + target_path + "\" " + args
    else:
        arguments = None

    creation_flags = CREATE_NEW_CONSOLE

    if suspend:    
        creation_flags += CREATE_SUSPENDED

    if not KERNEL32.CreateProcessA(target_path,
                                   arguments,
                                   None,
                                   None,
                                   None,
                                   creation_flags,
                                   None,
                                   None,
                                   byref(startupinfo),
                                   byref(process_information)):
        log("Unable to create process \"%s\" with arguments \"%s\" (GLE=%s)."
            % (target_path, arguments, KERNEL32.GetLastError()), "ERROR")
        return (-1, -1)
    else:
        log("Launched process \"%s\" with arguments \"%s\", ID \"%d\" and " \
            "thread \"0x%08x\"."
            % (target_path,
               arguments,
               process_information.dwProcessId,
               process_information.hThread))

    pid = process_information.dwProcessId
    h_thread = process_information.hThread

    return (pid, h_thread)
