# Copyright (C) 2015 KillerInstinct, Updated 2016 for Cuckoo 2.0
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

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class Hidden_Window(Signature):
    name = "stealth_window"
    description = "A process created a hidden window"
    severity = 2
    categories = ["stealth"]
    authors = ["KillerInstinct"]
    minimum = "2.0"

    filter_apinames = set(["ShellExecuteExW", "CreateProcessInternalW"])

    def on_call(self, call, process):
        if call["api"] == "CreateProcessInternalW":
            clbuf = call["arguments"]["command_line"].lower()
            # Handle Powershell CommandLine Arguments
            if "powershell" in clbuf and (re.search("-win[ ]+hidden", clbuf) or re.search("-windowstyle[ ]+hidden", clbuf)):
                self.mark_call()
            # CREATE_NO_WINDOW flag
            elif call["flags"]["creation_flags"] == "CREATE_NO_WINDOW":
                self.mark_call()

        elif call["api"] == "ShellExecuteExW":
            if call["arguments"]["show_type"] == 0:
                self.mark_call()

    def on_complete(self):
        return self.has_marks()
