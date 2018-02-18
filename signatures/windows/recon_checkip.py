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
    authors = ["nex", "RedSocks"]
    minimum = "2.0"

    domains = [
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
        "ip-address.domaintools.com",
        "ipchicken.com",
        "www.whatismyip.ca",
        "showmyip.com",
        "www.formyip.com",
        "ip2location.com",
        "meineipadresse.de",
        "ip-lookup.net",
        "checkip.org",
        "geoiptool.com",
        "cmyip.com",
        "knowmyip.com",
        "whatismyip.everdot.org",
        "whatismyip.akamai.com",
        "whatismyip.com",
        "bot.whatismyipaddress.com",
        "showmyipaddress.com",
        "www.showmyipaddress.com",
        "www.getmyip.org",
        "www.checkip.org",
        "myip.nl",
        "www.myip.nl",
        "myip.dnsomatic.com",
        "www.geoip.co.uk",
        "ipecho.net",
        "wtfismyip.com",
        "ipinfo.io",
        "ip.anysrc.net",
        "checkip.amazonaws.com",
        "ipaddress.pro",
        "ip-api.com",
    ]

    def on_complete(self):
        for indicator in self.domains:
            domain = self.check_domain(pattern=indicator)
            if domain:
                self.mark_ioc("domain", domain)

        return self.has_marks()
