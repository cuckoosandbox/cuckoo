# Copyright (C) 2014 Jeremy Hedges
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

class VMPPacked(Signature):
    name = "packer_vmprotect"
    description = "The executable is likely packed with VMProtect"
    severity = 2
    categories = ["packer"]
    authors = ["Jeremy Hedges"]
    minimum = "0.5"

    def run(self):
        if "static" in self.results:
            if "pe_sections" in self.results["static"]:
                for section in self.results["static"]["pe_sections"]:
                    if section["name"].lower().startswith(".vmp"):
                        self.data.append({"section" : section})
                        return True

        return False
