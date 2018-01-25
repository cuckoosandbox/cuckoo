# Copyright (C) 2012 Claudio "nex" Guarnieri (@botherder)
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

class HookMouse(Signature):
    name = "antisandbox_mouse_hook"
    description = "Installs an hook procedure to monitor for mouse events"
    severity = 3
    categories = ["hooking", "anti-sandbox"]
    authors = ["nex"]
    minimum = "2.0"

    filter_apinames = "SetWindowsHookExA", "SetWindowsHookExW"

    def on_call(self, call, process):
        if call["arguments"]["hook_identifier"] in [7, 14]:
            if not call["arguments"]["thread_identifier"]:
                self.mark_call()
                return True
