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
from threading import Thread
from winappdbg import Debug, EventHandler, HexDump, CrashDump, win32

from cuckoo.logging import *
from cuckoo.paths import *

TRACE_PATH = os.path.join(CUCKOO_PATH, "instructions")

class DumpInstruction(EventHandler):
    def create_process(self, event):
        event.debug.start_tracing(event.get_tid())

    def create_thread(self, event):
        event.debug.start_tracing(event.get_tid())

    def single_step(self, event):
        thread = event.get_thread()
        pc = thread.get_pc()
        code = thread.disassemble(pc, 0x10)[0]

        trace_file = open(os.path.join(TRACE_PATH, "%s.csv" % event.get_pid()), "a")
        trace_file.write("\"0x%s\",\"%s\"\n"
                         % (HexDump.address(code[0]), code[2]))
        trace_file.close()

class TraceInstructions(Thread):
    def __init__(self, pid):
        Thread.__init__(self)
        self.pid = pid

    def run(self):
        if not os.path.exists(TRACE_PATH):
            try:
                os.mkdir(TRACE_PATH)
            except (IOError, os.error), why:
                log("Unable to create folder \"%s\": %s" (TRACE_PATH, why), "ERROR")
                return False

        debug = Debug(DumpInstruction(), bKillOnExit = True, bHostileCode = True)
        try:
            debug.attach(self.pid)
            debug.loop()
        finally:
            debug.stop()

        return True
