# Copyright (C) 2012 Michael Boman (@mboman)
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

class UPXCompressed(Signature):
    name = "packer_upx"
    description = "The executable is compressed using UPX"
    severity = 2
    categories = ["packer"]
    authors = ["Michael Boman", "nex"]
    minimum = "2.0"

    def on_complete(self):
        for section in self.get_results("static", {}).get("pe_sections", []):
            if section["name"].startswith("UPX"):
                self.mark(section=section["name"],
                          description="Section name indicates UPX")

        return self.has_marks()
