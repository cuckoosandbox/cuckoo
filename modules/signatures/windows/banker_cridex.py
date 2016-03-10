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
    categories = ["Banking", "Trojan"]
    families = ["Cridex"]
    authors = ["Robby Zeitfuchs", "@robbyFux", "RedSocks"]
    minimum = "2.0"

    references = [
        "http://stopmalvertising.com/rootkits/analysis-of-cridex.html",
        "http://sempersecurus.blogspot.de/2012/08/cridex-analysis-using-volatility.html",
        "http://labs.m86security.com/2012/03/the-cridex-trojan-targets-137-financial-organizations-in-one-go/",
        "https://malwr.com/analysis/NDU2ZWJjZTIwYmRiNGVmNWI3MDUyMGExMGQ0MmVhYTY/",
        "https://malwr.com/analysis/MTA5YmU4NmIwMjg5NDAxYjlhYzZiZGIwYjZkOTFkOWY/",
    ]

    indicators = [
        ".*Local.QM.*",
        ".*Local.XM.*",
        "634I",
        "634M",
        "4BD88DEBRM",
        "6E8I",
        "6E8M",
        "404I",
        "404M",
        "714I",
        "714M",
        ".*XMI00000.*",
        ".*XMM00000.*",
        "87b3c64lkj48gd",
    ]

    def on_complete(self):
        match_file = self.check_file(pattern=".*\\\\KB[0-9]{8}\.exe", regex=True)
        if match_file:
            self.mark_ioc("file", match_file)

        match_batch_file = self.check_file(pattern=".*\\\\Temp\\\\\S{4,5}\.tmp\.bat", regex=True)
        if match_batch_file:
            self.mark_ioc("file", match_batch_file)

        if not match_file or not match_batch_file:
            return

        for indicator in self.indicators:
            match_mutex = self.check_mutex(pattern=indicator, regex=True)
            if match_mutex:
                self.mark_ioc("mutex", match_mutex)

        return self.has_marks(3)
