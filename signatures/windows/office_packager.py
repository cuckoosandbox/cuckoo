# Copyright (C) 2016 Claudio "nex" Guarnieri
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

class OfficePackager(Signature):
    name = "office_packager"
    description = "Microsoft Office process executed an embedded Packager Shell Object"
    severity = 3
    categories = ["dropper", "office"]
    authors = ["nex"]
    minimum = "2.0"

    filter_apinames = [
        "CreateProcessInternalW",
    ]

    filter_process_names = [
        "POWERPNT.EXE",
    ]

    def on_call(self, call, process):
        if process["process_name"] not in self.filter_process_names:
            return

        # TODO: Need to check whether this could cause some false positives.
        # Perhaps combine with some file creation "Embedded object".
        cmd_line = call["arguments"].get("command_line")
        if "packager.exe -Embedding" in cmd_line:
            self.mark_call()
            return True
