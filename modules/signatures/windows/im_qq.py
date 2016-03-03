# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class im_qq(Signature):
    name = "im_qq"
    description = "Connects to Chinese QQ Instant Messenger Service IP"
    severity = 2
    categories = ["im"]
    authors = ["RedSocks"]
    minimum = "2.0"

    ipaddrs = [
        "183.60.18.111",
        "112.95.234.84",
        "103.7.30.140",
        "140.207.69.49",
    ]

    def on_complete(self):
        for indicator in self.ipaddrs:
            if self.check_ip(pattern=indicator):
                self.mark_ioc("ipaddr", indicator)

        return self.has_marks()
