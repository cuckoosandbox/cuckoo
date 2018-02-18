# Copyright (C) 2015 KillerInstinct, Updated 2016 for cuckoo 2.0
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

class Multiple_UA(Signature):
    name = "multiple_useragents"
    description = "Network activity contains more than one unique useragent"
    severity = 3
    categories = ["network"]
    authors = ["KillerInstinct"]
    minimum = "2.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.useragents = list()
        self.procs = list()

    filter_analysistypes = set(["file"])
    filter_apinames = set(["InternetOpenA", "InternetOpenW"])

    def on_call(self, call, process):
        # Dict whitelist with process name as key, and useragents as values
        whitelist = {
            "acrord32.exe": ["Mozilla/3.0 (compatible; Acrobat 5.0; Windows)"],
            "iexplore.exe": ["VCSoapClient", "Shockwave Flash"],
        }
        ua = call["arguments"]["user_agent"]
        proc = process["process_name"].lower()
        if proc in whitelist.keys() and ua in whitelist[proc]:
            return None

        else:
            if ua not in self.useragents:
                self.useragents.append(ua)
                self.procs.append((process["process_name"], ua))

    def on_complete(self):
        if len(self.useragents) > 1:
            for item in self.procs:
                self.mark(
                    process=item[0],
                    useragent=item[1],
                )

        return self.has_marks()
