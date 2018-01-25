# Copyright (C) 2015 Optiv Inc. (brad.spengler@optiv.com), Updated 2016 for Cuckoo 2.0
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

import sys

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class CreatesLargeKey(Signature):
    name = "creates_largekey"
    description = "Creates or sets a registry key to a long series of bytes, possibly to store a binary or malware config"
    severity = 3
    categories = ["stealth"]
    authors = ["Optiv"]
    minimum = "2.0"
    evented = True

    filter_apinames = set(["NtSetValueKey", "RegSetValueExA", "RegSetValueExW"])

    whitelist = [
        ".*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\StartPage2\\\\ProgramsCache$",
    ]

    def on_call(self, call, process):
        if call["status"]:
            vallen = sys.getsizeof(call["arguments"]["value"])
            if vallen:
                length = int(vallen)
                if length > 16 * 1024:
                    for whitelist in self.whitelist:
                        if not re.match(whitelist, call["arguments"]["regkey"]):    
                            self.mark_call()

    def on_complete(self):
        return self.has_marks()
