# Copyright (C) 2013 Lord Alfred Remorin
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

from math import fabs

from lib.cuckoo.common.abstracts import Signature

try:
    import pydeep
    HAVE_SSDEEP = True
except ImportError:
    HAVE_SSDEEP = False

class Polymorphic(Signature):
    name = "packer_polymorphic"
    description = "Creates a slightly modified copy of itself"
    severity = 3
    categories = ["packer"]
    authors = ["lordr"]
    minimum = "2.0"

    def on_complete(self):
        if not HAVE_SSDEEP:
            return

        if self.get_results("target", {}).get("category") != "file":
            return

        target_ssdeep = self.get_results("target", {})["file"]["ssdeep"]
        target_sha1 = self.get_results("target", {})["file"]["sha1"]
        target_size = self.get_results("target", {})["file"]["size"]

        if not target_ssdeep:
            return

        for drop in self.get_results("dropped", []):
            if drop["sha1"] == target_sha1:
                continue

            if fabs(target_size - drop["size"]) >= 1024:
                continue

            drop_ssdeep = drop["ssdeep"]
            if not drop_ssdeep:
                continue

            if pydeep.compare(target_ssdeep, drop_ssdeep) > 20:
                self.mark(file=drop, description="Possibly a polymorphic version of itself")

        return self.has_marks()
