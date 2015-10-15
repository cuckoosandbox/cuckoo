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

class SystemInfo(Signature):
    name = "recon_systeminfo"
    description = "Collects information on the system (ipconfig, netstat, systeminfo)"
    severity = 3
    categories = ["recon"]
    authors = ["nex"]
    minimum = "1.2"
    evented = True

    def on_call(self, call, process):
        subject = self.check_argument_call(
            call, pattern="^cmd\.exe.*(systeminfo|ipconfig|netstat)",
            name="CommandLine",
            category="process",
            regex=True
        )
        if subject:
            self.add_match(process, 'api', call)

    def on_complete(self):
        return self.has_matches()
