# Copyright (C) 2014 Optiv Inc. (brad.spengler@optiv.com), Updated 2016 for Cuckoo 2.0
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

class Dropper(Signature):
    name = "dropper"
    description = "Drops a binary and executes it"
    severity = 2
    categories = ["dropper"]
    authors = ["Optiv"]
    minimum = "2.0"

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.executed = []
        self.exe = False
        if self.get_results("target", {}).get("category") == "file":
            f = self.get_results("target", {}).get("file", {})
            if "PE32 executable" in f.get("type", ""):
                self.exe = True

    filter_apinames = "CreateProcessInternalW", "ShellExecuteExW"

    def on_call(self, call, process):
        filepath = call["arguments"]["filepath"]
        if filepath not in self.executed:
            self.executed.append(filepath)

    def on_complete(self):
        for executed in self.executed:
            for dropped in self.get_results("dropped", []):
                if "filepath" in dropped:
                    filepath = dropped["filepath"]
                    if executed == filepath:
                        self.mark_ioc("file", executed)
                        if not self.exe:
                            self.severity = 3

        return self.has_marks()
