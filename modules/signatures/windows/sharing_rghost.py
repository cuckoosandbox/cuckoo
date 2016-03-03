# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class SharingRGhost(Signature):
    name = "sharing_rghost"
    description = "Connects to Russian file sharing service RGhost.net"
    severity = 2
    categories = ["filesharing"]
    authors = ["RedSocks"]
    minimum = "2.0"

    ipaddrs = [
        "89.248.225.50",
    ]

    def on_complete(self):
        for ipaddr in self.ipaddrs:
            if self.check_ip(pattern=ipaddr):
                self.mark_ioc("ipaddr", ipaddr)

        return self.has_marks()
