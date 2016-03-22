# Copyright (C) 2012 Thomas "stacks" Birn (@stacksth)
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

class InstallsWinpcap(Signature):
    name = "sniffer_winpcap"
    description = "Installs WinPCAP"
    severity = 3
    categories = ["sniffer"]
    authors = ["Thomas Birn", "nex"]
    minimum = "2.0"

    indicators = [
        ".*\\\\packet\\.dll$",
        ".*\\\\npf\\.sys$",
        ".*\\\\wpcap\\.dll$"
    ]

    def on_complete(self):
        for indicator in self.indicators:
            filepath = self.check_file(pattern=indicator, regex=True)
            if filepath:
                self.mark_ioc("file", filepath)

        return self.has_marks()
