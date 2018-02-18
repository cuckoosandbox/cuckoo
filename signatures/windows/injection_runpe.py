# Copyright (C) 2014 glysbays, Accuvant
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature

class InjectionRunPE(Signature):
    """Works much like InjectionThread from injection_thread.py - so please
    read its comment there to find out about the internal workings of this
    signature."""

    name = "injection_runpe"
    description = "Executed a process and injected code into it, probably while unpacking"
    severity = 5
    categories = ["injection"]
    authors = ["glysbaysb", "Accuvant"]
    minimum = "2.0"

    filter_apinames = [
        "CreateProcessInternalW",
        "NtUnmapViewOfSection",
        "NtAllocateVirtualMemory",
        "NtGetContextThread",
        "WriteProcessMemory",
        "NtWriteVirtualmemory",
        "NtMapViewOfSection",
        "NtSetContextThread",
        "NtResumeThread",
    ]

    _current_process_handles = "0xffffffff", "0xffffffffffffffff"

    def init(self):
        self.functions = {}

    def on_process(self, process):
        self.functions[process["pid"]] = set()

    def on_call(self, call, process):
        # We don't care about the current process.
        process_handle = call["arguments"].get("process_handle")
        if process_handle in self._current_process_handles:
            return

        self.functions[process["pid"]].add(call["api"])
        self.mark_call()

    def on_complete(self):
        for pid, functions in self.functions.items():
            if len(functions) >= 4:
                return True
