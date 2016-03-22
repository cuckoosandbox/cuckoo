# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class dnsserver_dynamic(Signature):
    name = "dnsserver_dynamic"
    description = "Connects to DNS Servers of Dynamic DNS Provider"
    severity = 2
    categories = ["dns"]
    authors = ["RedSocks"]
    minimum = "2.0"

    ipaddrs = [
        "221.228.198.216",
        "61.160.239.11",
        "50.31.129.129",
        "165.254.162.241",
        "69.65.40.108",
        "180.92.187.122",
        "50.23.197.95",
        "208.43.71.243",
        "69.197.18.162",
        "70.39.97.253",
    ]

    def on_complete(self):
        for indicator in self.ipaddrs:
            if self.check_ip(pattern=indicator):
                self.mark_ioc("ipaddr", indicator)
                return True
