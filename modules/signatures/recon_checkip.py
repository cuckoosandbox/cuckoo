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

class CheckIP(Signature):
    name = "recon_checkip"
    description = "Looks up the external IP address"
    severity = 2
    categories = ["recon"]
    authors = ["nex"]
    minimum = "1.2"

    def run(self):
        indicators = [
            "checkip.dyndns.com",
            "checkip.dyndns.org",
            "whatismyip.org",
            "whatsmyipaddress.com",
            "getmyip.org",
            "getmyip.co.uk",
            "icanhazip.com",
            "whatismyipaddress.com",
            "myipaddress.com",
            "ip-addr.es",
            "api.ipify.org",
            "ipinfo.info",
            "myexternalip.com",
        ]

        for indicator in indicators:
            subject = self.check_domain(pattern=indicator)
            if subject:
                self.add_match(None, 'domain', subject)

        return self.has_matches()
