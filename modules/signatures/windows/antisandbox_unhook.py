# Copyright (C) 2014 Claudio "nex" Guarnieri (@botherder)
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

class Unhook(Signature):
    name = "antisandbox_unhook"
    description = "Tries to unhook Windows functions monitored by Cuckoo"
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["nex"]
    minimum = "2.0"

    filter_apinames = "__anomaly__",

    def on_call(self, call, process):
        self.mark_call()
        return True
