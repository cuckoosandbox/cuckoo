# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Smtp_Yahoo(Signature):
    name = "smtp_yahoo"
    description = "Connects to smtp.mail.yahoo.com, possibly for spamming or data exfiltration"
    severity = 2
    categories = ["smtp"]
    authors = ["RedSocks"]
    minimum = "2.0"

    domains = [
        "smtp.mail.yahoo.com",
    ]

    def on_complete(self):
        for indicator in self.domains:
            if self.check_domain(pattern=indicator):
                self.mark_ioc("domain", indicator)
                return True
