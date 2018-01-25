# Copyright (C) 2012,2015 Claudio "nex" Guarnieri (@botherder), Optiv, Inc. (brad.spengler@optiv.com)
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

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class ADS(Signature):
    name = "persistence_ads"
    description = "Creates an Alternate Data Stream (ADS)"
    severity = 3
    categories = ["persistence", "ads"]
    authors = ["nex", "Optiv"]
    minimum = "2.0"

    def on_complete(self):
        for filepath in self.get_files():
            if len(filepath) <= 3:
                continue

            if ":" in filepath.split("\\")[-1]:
                if not filepath.lower().startswith("c:\\dosdevices\\") and not filepath[-1] == ":":
                    # we have a different signature to deal with removal of Zone.Identifier
                    if not filepath.startswith("\\??\\http://") and not filepath.endswith(":Zone.Identifier") and not re.match(r'^[A-Z]?:\\(Users|Documents and Settings)\\[^\\]+\\Favorites\\Links\\Suggested Sites\.url:favicon$', filepath, re.IGNORECASE):
                        self.mark_ioc("file", filepath)

        return self.has_marks()
