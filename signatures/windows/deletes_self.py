# Copyright (C) 2014 Optiv Inc. (brad.spengler@optiv.com), Converted 2016 for Cuckoo 2.0
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

class DeletesSelf(Signature):
    name = "deletes_self"
    description = "Deletes its original binary from disk"
    severity = 3
    categories = ["persistence", "stealth"]
    authors = ["Optiv", "Kevin Ross"]
    minimum = "2.0"
    evented = True

    def on_complete(self):
        processes = []
        for process in self.get_results("behavior", {}).get("generic", []):
            for cmdline in process.get("summary", {}).get("command_line", []):
                processes.append(cmdline)

        if processes:
            for deletedfile in self.get_files(actions=["file_deleted"]):
                if deletedfile in processes[0]:
                    self.mark_ioc("file", deletedfile)

        return self.has_marks()
