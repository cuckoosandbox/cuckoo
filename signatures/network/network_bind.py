# Copyright (C) 2013 Claudio "nex" Guarnieri (@botherder), Accuvant, Inc. (bspengler@accuvant.com)
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

class NetworkBIND(Signature):
    name = "network_bind"
    description = "Starts servers listening"
    severity = 2
    categories = ["bind"]
    authors = ["nex", "Accuvant"]
    minimum = "2.0"

    filter_apinames = "bind", "listen", "accept"

    def init(self):
        self.mask = 0

    def on_call(self, call, process):
        if call["api"] == "bind":
            self.mark_call()
            self.mask |= 1

        if call["api"] == "listen":
            self.mark_call()
            self.mask |= 2

        if call["api"] == "accept":
            self.mark_call()
            self.mask |= 4

    def on_complete(self):
        return self.mask == 7
