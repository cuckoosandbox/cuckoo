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

class ZeusURL(Signature):
    name = "banker_zeus_url"
    description = "Contacts C&C server HTTP check-in (Banking Trojan)"
    severity = 3
    categories = ["banker"]
    authors = ["Robby Zeitfuchs"]
    minimum = "1.2"
    references = ["https://zeustracker.abuse.ch/blocklist.php?download=compromised"]

    def run(self):
        indicators = [
            ".*\/config\.bin",                                  
            ".*\/gate\.php",                               
            ".*\/cfg\.bin",                                   
        ]

        for indicator in indicators:
            match = self.check_url(pattern=indicator, regex=True)
            if match:
                self.add_match(None, 'url', match)
        
        return self.has_matches()
