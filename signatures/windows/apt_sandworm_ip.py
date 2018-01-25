# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class apt_sandworm_ip(Signature):
    name = "apt_sandworm_ip"
    description = "Connects to Known Sandworm APT IP address"
    severity = 2
    categories = ["apt"]
    authors = ["RedSocks"]
    minimum = "2.0"

    ipaddrs = [
        "95.143.193.131",
        "46.165.222.6",
        "78.46.40.239",
        "144.76.119.48",
        "37.220.34.56",
        "46.4.28.218",
        "95.143.193.182",
        "5.61.38.31",
        "94.185.80.66",
        "95.211.122.36"
    ]

    def on_complete(self):
        for ipaddr in self.ipaddrs:
            if self.check_ip(pattern=ipaddr):
                self.mark_ioc("ipaddr", ipaddr)

        return self.has_marks()
