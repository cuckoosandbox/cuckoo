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

import re
from lib.cuckoo.common.abstracts import Signature

class ZeusP2P(Signature):
    name = "banker_zeus_p2p"
    description = "Zeus P2P (Banking Trojan)"
    severity = 3
    categories = ["banker"]
    families = ["zeus"]
    authors = ["Robby Zeitfuchs"]
    minimum = "1.2"
    references = ["https://malwr.com/analysis/NmNhODg5ZWRkYjc0NDY0M2I3YTJhNDRlM2FlOTZiMjA/", 
                  "https://malwr.com/analysis/MmMwNDJlMTI0MTNkNGFjNmE0OGY3Y2I5MjhiMGI1NzI/",
                  "https://malwr.com/analysis/MzY5ZTM2NzZhMzI3NDY2YjgzMjJiODFkODZkYzIwYmQ/",
                  "https://www.virustotal.com/de/file/301fcadf53e6a6167e559c84d6426960af8626d12b2e25aa41de6dce511d0568/analysis/#behavioural-info",
                  "https://www.virustotal.com/de/file/d3cf49a7ac726ee27eae9d29dee648e34cb3e8fd9d494e1b347209677d62cdf9/analysis/#behavioural-info",
                  "https://www.virustotal.com/de/file/d3cf49a7ac726ee27eae9d29dee648e34cb3e8fd9d494e1b347209677d62cdf9/analysis/#behavioural-info",
                  "https://www.virustotal.com/de/file/301fcadf53e6a6167e559c84d6426960af8626d12b2e25aa41de6dce511d0568/analysis/#behavioural-info"]

    def run(self):
        # Check zeus synchronization-mutex.
        # Regexp pattern for zeus synchronization-mutex such as for example:
        # 2CCB0BFE-ECAB-89CD-0261-B06D1C10937F
        exp = re.compile(".*[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}", re.IGNORECASE)
        mutexes = self.results["behavior"]["summary"]["mutexes"]
        
        count = 0
        for mutex in mutexes:
            if exp.match(mutex):
                self.add_match(None, 'mutex', mutex)
                count += 1 

        # Check if there are at least 5 mutexes opened matching the pattern?   
        if count < 5:
            return False
        
        # Check for UDP Traffic on remote port greater than 1024.
        # TODO: this might be faulty without checking whether the destination
        # IP is really valid.
        count = 0
        if "network" in self.results:
            for udp in self.results["network"]["udp"]:
                if udp["dport"] > 1024:
                    self.add_match(None, 'udp', udp)
                    count += 1
            
        if count < 4:
            return False
    
        return True
