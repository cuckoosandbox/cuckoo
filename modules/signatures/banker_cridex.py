# Copyright (C) 2014 Robby Zeitfuchs (@robbyFux)
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

class Cridex(Signature):
    name = "banker_cridex"
    description = "Cridex banking trojan"
    severity = 3
    alert = True
    categories = ["Banking", "Trojan"]
    families = ["Cridex"]
    authors = ["Robby Zeitfuchs", "@robbyFux"]
    minimum = "1.2"
    references = ["http://stopmalvertising.com/rootkits/analysis-of-cridex.html",
                  "http://sempersecurus.blogspot.de/2012/08/cridex-analysis-using-volatility.html",
                  "http://labs.m86security.com/2012/03/the-cridex-trojan-targets-137-financial-organizations-in-one-go/",
                  "https://malwr.com/analysis/NDU2ZWJjZTIwYmRiNGVmNWI3MDUyMGExMGQ0MmVhYTY/",
                  "https://malwr.com/analysis/MTA5YmU4NmIwMjg5NDAxYjlhYzZiZGIwYjZkOTFkOWY/"]

    def run(self):
        indicators = [".*Local.QM.*",
                      ".*Local.XM.*"]
        signs = {}
                      
        match_file = self.check_file(pattern=".*\\\\KB[0-9]{8}\.exe", regex=True)
        match_batch_file = self.check_file(pattern=".*\\\\Temp\\\\\S{4,5}\.tmp\.bat", regex=True)

        if match_file and match_batch_file:
            signs['file'] = match_file
            signs['batchfile'] = match_batch_file
            for indicator in indicators:
                match_mutex = self.check_mutex(pattern=indicator, regex=True)
                if match_mutex:
                    signs['mutex'] = match_mutex
                    self.add_match(None, 'cridex_ioc', signs)
                    return True

        return False
