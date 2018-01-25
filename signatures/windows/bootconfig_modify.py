# Copyright (C) 2016 Kevin Ross
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

class ModifiesBootConfig(Signature):
    name = "modifies_boot_config"
    description = "Modifies boot configuration settings"
    severity = 3
    categories = ["persistance", "ransomware"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    filter_apinames = "ShellExecuteExW", "CreateProcessInternalW",

    def on_call(self, call, process):
        if call["api"] == "CreateProcessInternalW":
            buf = call["arguments"]["command_line"].lower()
        else:
            buf = call["arguments"]["filepath"].lower()
        if "bcdedit" in buf and "set" in buf:
            self.mark_ioc("command", buf)

    def on_complete(self):
        return self.has_marks()
