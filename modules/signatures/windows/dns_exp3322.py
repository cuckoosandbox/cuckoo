# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class exp_3322_dom(Signature):
    name = "exp_3322_dom"
    description = "Connects to expired 3322.org or related domain (125.77.199.30)"
    severity = 2
    categories = ["expdom"]
    authors = ["RedSocks"]
    minimum = "2.0"

    ipaddrs = [
        "125.77.199.30",
    ]

    def on_complete(self):
        for indicator in self.ipaddrs:
            if self.check_ip(pattern=indicator):
                self.mark_ioc("ipaddr", indicator)
                return True
