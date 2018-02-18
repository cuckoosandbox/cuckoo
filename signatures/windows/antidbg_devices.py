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

class AntiDBGDevices(Signature):
    name = "antidbg_devices"
    description = "Checks for the presence of known devices from debuggers and forensic tools"
    severity = 3
    categories = ["anti-debug"]
    authors = ["nex"]
    minimum = "2.0"

    indicators = [
        ".*SICE$",
        ".*SIWVID$",
        ".*SIWDEBUG$",
        ".*NTICE$",
        ".*REGVXG$",
        ".*FILEVXG$",
        ".*REGSYS$",
        ".*FILEM$",
        ".*TRW$",
        ".*ICEXT$"
    ]

    def on_complete(self):
        for indicator in self.indicators:
            for filepath in self.check_file(pattern=indicator, regex=True, all=True):
                self.mark_ioc("file", filepath)

        return self.has_marks()
