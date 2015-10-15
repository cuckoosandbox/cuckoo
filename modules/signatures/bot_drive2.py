# Copyright (C) 2014 jjones
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

class Drive2(Signature):
    name = "bot_drive2"
    description = "Recognized to be a Drive2 bot"
    severity = 3
    categories = ["bot", "ddos"]
    families = ["drive2"]
    authors = ["jjones", "nex"]
    minimum = "1.2"

    def run(self):
        regexp = "Mozilla/5.0 \(Windows NT [56].1; (WOW64; )?rv:(9|1[0-7]).0\) " \
                 "Gecko/20100101 Firefox/(9|1[0-7]).0|Mozilla/4.0 \(compatible; " \
                 "MSIE 8.0; Windows NT [56].1; (WOW64; )Trident/4.0; SLCC2; .NET " \
                 "CLR 2.0.[0-9]{6}; .NET CLR 3.5.[0-9]{6}; .NET CLR 3.0.[0-9]{6}|Opera/9.80 " \
                 "\(Windows NT [56].1; (WOW64; )U; Edition [a-zA-Z]+ Local; ru\) Presto/2.10.289 " \
                 "Version/([5-9]|1[0-2]).0[0-9]"

        drive_ua_re = re.compile(regexp)
        if "network" in self.results:
            for http in self.results["network"]["http"]:
                if http["method"] == "POST" and (http["body"].startswith("req=") or http["body"].startswith("newd=1")) and drive_ua_re.search(http.get("user-agent", "")):
                    self.add_match(None, 'http', http)

        return self.has_matches()
