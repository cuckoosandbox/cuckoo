# Copyright (C) 2016 Claudio "nex" Guarnieri (@botherder)
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

class ZoneID(Signature):
    name = "modifies_zoneid"
    description = "Modifies the ZoneTransfer.ZoneID in Zone.Identifier ADS, " \
        "generally to disable security warnings"
    severity = 2
    categories = [""]
    authors = ["nex"]
    minimum = "2.0"

    filter_apinames = "NtCreateFile", "NtWriteFile"

    def init(self):
        self.zone_handle = None

    def on_call(self, call, process):
        if call["api"] == "NtCreateFile":
            file_path = call["arguments"]["filepath"].lower()
            if file_path.endswith(":zone.identifier"):
                self.zone_handle = call["arguments"]["file_handle"]
                self.mark_call()

        if call["api"] == "NtWriteFile" and self.zone_handle:
            buf = call["arguments"]["buffer"].lower()
            if "[zonetransfer]" in buf and "zoneid" in buf:
                self.mark_call()
                return True
