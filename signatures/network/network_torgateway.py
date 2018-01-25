# Copyright (C) 2014 Claudio "nex" Guarnieri (@botherder), Optiv, Inc. (brad.spengler@optiv.com)
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

class TorGateway(Signature):
    name = "network_torgateway"
    description = "Connects to Tor Hidden Services through a Tor gateway"
    severity = 3
    categories = ["network"]
    authors = ["nex", "Optiv"]
    minimum = "2.0"

    domains_re = [
        ".*\\.tor2web\\.[a-z]{2,20}$",
        ".*\\.onion\\.[a-z]{2,20}$",
        ".*\.bortor\.com$",
        ".*\.torpacho\.com$",
        ".*\.torsanctions\.com$",
        ".*\.torwild\.com$",
        ".*\.pay2tor\.com$",
        ".*\.tor2pay\.com$",
        ".*\.tor4pay\.com$",
        ".*\.pay4tor\.com$",
        ".*\.torexplorer\.com$",
        ".*\.tor\-gateways\.de$",
        ".*\.torpaycash\.com$",
        ".*\.torconnectpay\.com$",
        ".*\.torwalletpay\.com$",
        ".*\.walterwhitepay\.com$",
        ".*\.rossulbrichtpay\.com$",
        ".*\.42k2bu15\.com$",
        ".*\.79fhdm16\.com$",
        ".*\.myportopay\.com$",
        ".*\.vivavtpaymaster\.com$",
        ".*\.fraspartypay\.com$",
    ]

    def on_complete(self):
        for regex in self.domains_re:
            for domain in self.check_domain(pattern=regex, regex=True, all=True):
                self.mark_ioc("domain", domain)

        return self.has_marks()
