# Copyright (C) 2012 Claudio "nex" Guarnieri (@botherder)
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

class ADS(Signature):
    name = "persistence_ads"
    description = "Creates an Alternate Data Stream (ADS)"
    severity = 3
    categories = ["persistence", "ads"]
    authors = ["nex"]
    minimum = "2.0"

    def on_complete(self):
        for filepath in self.get_files():
            parts = filepath.replace("/", "\\").split("\\")
            if ":" in parts[-1]:
                self.mark_ioc("file", filepath)
