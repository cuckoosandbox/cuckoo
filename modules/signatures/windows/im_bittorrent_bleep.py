# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class im_btb(Signature):
    name = "im_btb"
    description = "Connects to BitTorrent Bleepchat IP"
    severity = 2
    categories = ["im"]
    authors = ["RedSocks"]
    minimum = "2.0"

    ipaddrs = [
        "23.21.70.220",
        "54.243.240.224",
        "54.225.243.50",
        "54.225.152.58",
        "54.235.137.132",
        "54.204.31.170",
        "54.230.12.225",
        "107.21.220.158",
        "103.7.30.140",
        "112.95.234.84",
        "183.60.18.111",
        "54.235.164.20",
    ]

    def on_complete(self):
        for indicator in self.ipaddrs:
            if self.check_ip(pattern=indicator):
                self.mark_ioc("ipaddr", indicator)

        return self.has_marks()
