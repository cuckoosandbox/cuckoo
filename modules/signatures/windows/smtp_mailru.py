# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Smtp_Mail_Ru(Signature):
    name = "smtp_mail_ru"
    description = "Connects to smtp.mail.ru, possibly for spamming or data exfiltration"
    severity = 2
    categories = ["smtp"]
    authors = ["RedSocks"]
    minimum = "2.0"

    ipaddrs = [
        "94.100.180.160",
    ]

    def on_complete(self):
        for indicator in self.ipaddrs:
            if self.check_ip(pattern=indicator):
                self.mark_ioc("ipaddr", indicator)

        return self.has_marks()
