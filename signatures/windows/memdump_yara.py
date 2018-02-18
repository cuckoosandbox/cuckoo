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

class ProcMemDumpYara(Signature):
    name = "memdump_yara"
    description = "Yara rule detected in process memory"
    severity = 2
    categories = ["generic"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    malicious_rules = [
    "Ransomware_Message",
    ]

    def on_complete(self):
        for procmem in self.get_results("procmemory", []):
            for yara in procmem.get("yara", []):
                yararule = yara["name"]
                ruledescription = yara["meta"]["description"]
                self.mark(
                    rule=yararule,
                    description=ruledescription,                      
                )
                if yararule in self.malicious_rules:
                    self.severity = 3

        return self.has_marks()
