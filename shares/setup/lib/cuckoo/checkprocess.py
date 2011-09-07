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

sys.path.append("\\\\VBOXSVR\\setup\\lib")

from cuckoo.defines import *
from cuckoo.logging import *

def check_process(pid):
    h_process = KERNEL32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))

    if not h_process:
        return False

    exit_code = c_ulong(0)
    KERNEL32.GetExitCodeProcess(h_process, byref(exit_code))

    if exit_code.value == STILL_ACTIVE:
        return True
    else:
        return False
