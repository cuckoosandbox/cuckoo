# Copyright (C) 2012-2014 Claudio "nex" Guarnieri (@botherder)
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

class BrowserStealer(Signature):
    name = "infostealer_browser"
    description = "Steals private information from local Internet browsers"
    severity = 2
    categories = ["infostealer"]
    authors = ["nex"]
    minimum = "2.0"

    indicators = [
        ".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\signons\\.sqlite$",
        ".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\secmod\\.db$",
        ".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\cert8\\.db$",
        ".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\key3\\.db$",
        ".*\\\\Application\\ Data\\\\Google\\\\Chrome\\\\.*",
        ".*\\\\Application\\ Data\\\\Opera\\\\.*",
        ".*\\\\Application\\ Data\\\\Chromium\\\\.*",
        ".*\\\\Application\\ Data\\\\ChromePlus\\\\.*",
        ".*\\\\Application\\ Data\\\\Nichrome\\\\.*",
        ".*\\\\Application\\ Data\\\\Bromium\\\\.*",
        ".*\\\\Application\\ Data\\\\RockMelt\\\\.*",
    ]

    def on_complete(self):
        for indicator in self.indicators:
            for filepath in self.check_file(pattern=indicator, regex=True, all=True):
                self.mark_ioc("file", filepath)

        return self.has_marks()
