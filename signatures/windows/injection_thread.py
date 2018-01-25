# Copyright (C) 2012 JoseMi "h0rm1" Holguin (@j0sm1)
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

class InjectionThread(Signature):
    """Instead of overly complicated, and easily bypassable, handle tracking
    we're just looking at the functions that have been used in each process.
    If a subset containing the majority of the functions required for creating
    a remote thread have been used then we trigger this signature."""

    name = "injection_thread"
    description = "Code injection with CreateRemoteThread or NtQueueApcThread in a remote process"
    severity = 3
    categories = ["injection"]
    authors = ["JoseMi Holguin", "nex", "Accuvant"]
    minimum = "2.0"

    filter_apinames = [
        "NtOpenProcess",
        "NtMapViewOfSection",
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "NtQueueApcThread",
    ]

    def init(self):
        self.functions = {}

    def on_process(self, process):
        self.functions[process["pid"]] = set()

    def on_call(self, call, process):
        # We're not interested in events to the local process. TODO Is there a
        # better way to identify the current process?
        process_handle = call["arguments"].get("process_handle")
        if process_handle and process_handle.startswith("0xffffffff"):
            return

        self.functions[process["pid"]].add(call["api"])
        self.mark_call()

    def on_complete(self):
        for pid, functions in self.functions.items():
            if len(functions) >= len(self.filter_apinames)-3:
                return True
