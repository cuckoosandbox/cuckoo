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

class ZeusMutexes(Signature):
    name = "banker_zeus_mutex"
    description = "Creates Zeus (Banking Trojan) mutexes"
    severity = 3
    categories = ["banker"]
    families = ["zeus"]
    authors = ["Robby Zeitfuchs"]
    minimum = "2.0"

    references = [
        "https://malwr.com/analysis/NmNhODg5ZWRkYjc0NDY0M2I3YTJhNDRlM2FlOTZiMjA/#summary_mutexes",
        "https://malwr.com/analysis/MmMwNDJlMTI0MTNkNGFjNmE0OGY3Y2I5MjhiMGI1NzI/#summary_mutexes",
        "https://malwr.com/analysis/MzY5ZTM2NzZhMzI3NDY2YjgzMjJiODFkODZkYzIwYmQ/#summary_mutexes",
        "https://www.virustotal.com/de/file/301fcadf53e6a6167e559c84d6426960af8626d12b2e25aa41de6dce511d0568/analysis/#behavioural-info",
        "https://www.virustotal.com/de/file/d3cf49a7ac726ee27eae9d29dee648e34cb3e8fd9d494e1b347209677d62cdf9/analysis/#behavioural-info",
        "https://www.virustotal.com/de/file/d3cf49a7ac726ee27eae9d29dee648e34cb3e8fd9d494e1b347209677d62cdf9/analysis/#behavioural-info",
        "https://www.virustotal.com/de/file/301fcadf53e6a6167e559c84d6426960af8626d12b2e25aa41de6dce511d0568/analysis/#behavioural-info",
    ]

    indicators = [
        "_AVIRA_.*",
        "__SYSTEM__.*",
        "_LILO_.*",
        "_SOSI_.*",
        ".*MSIdent Logon",
        ".*MPSWabDataAccessMutex",
        ".*MPSWABOlkStoreNotifyMutex",
    ]

    def on_complete(self):
        for indicator in self.indicators:
            mutex = self.check_mutex(pattern=indicator, regex=True)
            if mutex:
                self.mark_ioc("mutex", mutex)

        return self.has_marks()
