# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class cloud_wetransfer(Signature):
    name = "cloud_wetransfer"
    description = "Connects to Wetransfer Cloud Storage Service"
    severity = 2
    categories = ["cloud"]
    authors = ["RedSocks"]
    minimum = "2.0"

    ipaddrs = [
        "176.34.228.190",
        "176.34.103.229",
        "46.137.91.111",
        "46.137.177.108",
        "54.247.163.235",
        "79.125.106.75",
        "176.34.177.108",
    ]

    def on_complete(self):
        for indicator in self.ipaddrs:
            if self.check_ip(pattern=indicator):
                self.mark_ioc("ipaddr", indicator)
                return True
