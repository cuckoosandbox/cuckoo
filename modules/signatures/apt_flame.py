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

class Flame(Signature):
    name = "targeted_flame"
    description = "Shows some indicators associated with the Flame malware"
    severity = 3
    references = ["http://www.crysys.hu/skywiper/skywiper.pdf",
                  "http://www.securelist.com/en/blog/208193522/The_Flame_Questions_and_Answers",
                  "http://www.certcc.ir/index.php?name=news&file=article&sid=1894"]
    categories = ["targeted"]
    families = ["flame", "skywiper"]
    authors = ["nex"]
    minimum = "1.2"

    def run(self):
        indicators = [
            "__fajb.*",
            "DVAAccessGuard.*",
            ".*mssecuritymgr.*"
        ]

        for indicator in indicators:
            subject = self.check_mutex(pattern=indicator, regex=True)
            if subject:
                self.add_match(None, 'mutex', subject)

        indicators = [
            ".*\\\\Microsoft Shared\\\\MSSecurityMgr\\\\.*",
            ".*\\\\Ef_trace\.log$"
        ]

        for indicator in indicators:
            subject = self.check_file(pattern=indicator, regex=True)
            if subject:
                self.add_match(None, 'file', subject)

        return self.has_matches()
