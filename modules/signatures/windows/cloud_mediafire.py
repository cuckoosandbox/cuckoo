# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class cloud_mediafire(Signature):
    name = "cloud_mediafire"
    description = "Connects to MediaFire Cloud Storage Service"
    severity = 2
    categories = ["cloud"]
    authors = ["RedSocks"]
    minimum = "2.0"

    ipaddrs = [
        "205.196.120.6",
        "205.196.120.8",
        "205.196.120.12",
        "205.196.120.13",
        "154.53.224.138",
        "154.53.224.146",
        "154.53.224.142",
    ]

    def on_complete(self):
        for indicator in self.ipaddrs:
            if self.check_ip(pattern=indicator):
                self.mark_ioc("ipaddr", indicator)
                return True
