# Copyright (C) 2016 Brad Spengler
#
# This program is free Software: you can redistribute it and/or modify
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

class PersistenceBootexecute(Signature):
    name = "persistence_bootexecute"
    description = "Installs a native executable to run on early Windows boot"
    severity = 3
    categories = ["persistence"]
    authors = ["Brad Spengler"]
    minimum = "2.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.registry_writes = dict()
        self.found_bootexecute = False

    filter_apinames = set(["RegSetValueExA", "RegSetValueExW", "NtSetValueKey"])

    def on_call(self, call, process):
        if call["status"]:
            fullname = call["arguments"]["regkey"]
            self.registry_writes[fullname] = call["arguments"]["value"]

    def on_complete(self):
        match_key = self.check_key(pattern=".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\Control\\\\Session\\ Manager\\\\(BootExecute|SetupExecute|Execute|S0InitialCommand)", regex=True, actions=["regkey_written"], all=True)
        if match_key:
            self.found_bootexecute = True
            for match in match_key:
                data = self.registry_writes.get(match, "unknown")
                self.data.append({"key" : match})
                self.data.append({"data" : data})


        return self.found_bootexecute
