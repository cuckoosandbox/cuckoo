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

sys.path.append("\\\\VBOXSVR\\setup\\lib\\")

from cuckoo.execute import *
from cuckoo.logging import *
from cuckoo.monitor import *

# The package main function "cuckoo_run" should follow a fixed structure in
# order for Cuckoo to correctly handle it and its results.
def cuckoo_run(target_path):
    # Every analysis package can retrieve a list of multiple process IDs it
    # might have generated. All processes added to this list will be added to
    # the monitored list, and Cuckoo will wait for all of the to complete their
    # execution before ending the analysis.
    pids = []

    # The following functions are used to launch a process with the simplified
    # "cuckoo_execute" function. This function takes as arguments (in specific
    # order):
    # - a path to the executable to launch
    # - arguments to be passed on execution
    # - a boolean value to specify if the process have to be created in
    #   suspended mode or not (it's recommended to set it to True if the
    #   process is supposed to be injected and monitored).
    suspended = True
    (pid, h_thread) = cuckoo_execute(target_path, None, suspended)
    # The function "cuckoo_monitor" invoke the DLL injection and resume the
    # process if it was suspended. It needs the process id and the main thread
    # handle returned by "cuckoo_execute" and the same boolean value to tell it
    # if it needs to resume the process.
    cuckoo_monitor(pid, h_thread, suspended)

    # Append all the process IDs you want to the list, and return the list.
    pids.append(pid)
    return pids

def cuckoo_check():
    return True

def cuckoo_finish():
    return True
