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

import re

from lib.cuckoo.common.abstracts import Signature

class BrowserStealer(Signature):
    name = "infostealer_browser"
    description = "Steals private information from local Internet browsers"
    severity = 3
    categories = ["infostealer"]
    authors = ["nex"]
    minimum = "1.2"
    evented = True

    indicators = [
        re.compile(".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\signons\.sqlite$"),
        re.compile(".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\secmod\.db$"),
        re.compile(".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\cert8\.db$"),
        re.compile(".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\key3\.db$"),
        re.compile(".*\\\\History\\\\History\.IE5\\\\index\.dat$"),
        re.compile(".*\\\\Temporary\\\\ Internet\\ Files\\\\Content\.IE5\\\\index\.dat$"),
        re.compile(".*\\\\Application\\ Data\\\\Google\\\\Chrome\\\\.*"),
        re.compile(".*\\\\Application\\ Data\\\\Opera\\\\.*"),
        re.compile(".*\\\\Application\\ Data\\\\Chromium\\\\.*"),
        re.compile(".*\\\\Application\\ Data\\\\ChromePlus\\\\.*"),
        re.compile(".*\\\\Application\\ Data\\\\Nichrome\\\\.*"),
        re.compile(".*\\\\Application\\ Data\\\\Bromium\\\\.*"),
        re.compile(".*\\\\Application\\ Data\\\\RockMelt\\\\.*")

    ]

    def on_call(self, call, process):
        # If the current process appears to be a browser, continue.
        if process["process_name"].lower() in ("iexplore.exe", "firefox.exe", "chrome.exe"):
            return None

        # If the call category is not filesystem, continue.
        if call["category"] != "filesystem":
            return None

        for argument in call["arguments"]:
            if argument["name"] == "FileName":
                for indicator in self.indicators:
                    if indicator.match(argument["value"]):
                        self.add_match(process, 'api', call)

    def on_complete(self):
        return self.has_matches()
