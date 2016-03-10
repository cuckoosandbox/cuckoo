# Copyright (C) 2015 Claudio "nex" Guarnieri
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

class Adzok(Signature):
    name = "rat_adzok"
    description = "Creates known Adzok RAT files"
    severity = 3
    categories = ["rat"]
    families = ["adzok"]
    authors = ["nex"]
    minimum = "2.0"
    
    indicators = [
        ".*\\\\Adzoklock.tmp",
    ]

    def on_complete(self):
        for indicator in self.indicators:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("file", match)

        return self.has_marks()
