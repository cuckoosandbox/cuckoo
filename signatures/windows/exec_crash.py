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

class Crash(Signature):
    name = "exec_crash"
    description = "At least one process apparently crashed during execution"
    severity = 1
    categories = ["execution", "crash"]
    authors = ["nex"]
    minimum = "2.0"

    filter_apinames = "LdrLoadDll",

    def on_call(self, call, process):
        if "faultrep.dll" in call["arguments"]["module_name"].lower():
            self.mark_call()
            return True
