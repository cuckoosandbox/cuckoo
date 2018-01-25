# Copyright (C) 2017 Kevin Ross
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

class Emotet_APIs(Signature):
    name = "emotet_behavior"
    description = "Exhibits behavior characteristic of Emotet malware"
    severity = 3
    categories = ["infostealer", "banker"]
    families = ["emotet"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    evented = True
    references = ["blogs.forcepoint.com/security-labs/new-variant-geodoemotet-banking-malware-targets-uk"]

    compname = []
    processlist = []

    filter_apinames = set(["GetComputerNameW", "Process32NextW", "CryptEncrypt"])

    def on_call(self, call, process):
        if call["api"] == "GetComputerNameW":
            compname = call["arguments"]["computer_name"]
            if compname not in self.compname:
                self.compname.append(compname)

        elif call["api"] == "Process32NextW":
            procname = call["arguments"]["process_name"]
            if procname not in self.processlist:
                self.processlist.append(procname)

        elif call["api"] == "CryptEncrypt":
            buf = call["arguments"]["buffer"]
            if "[System Process]" in buf:
                for compname in self.compname:
                    if compname in buf:
                        count = 0
                        for proc in self.processlist:
                            if proc in buf:
                                count += 1
                        if count > 5:
                            self.mark_call()

    def on_complete(self):
        return self.has_marks()
