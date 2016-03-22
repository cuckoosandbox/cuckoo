# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DNS_TLD_RU(Signature):
    name = "dns_tld_ru"
    description = "Resolves .RU Russia TLD, Possibly Malicious"
    severity = 2
    categories = ["tldwatch"]
    authors = ["RedSocks"]
    minimum = "2.0"

    domains_re = [
        ".*\\.ru$",
    ]

    def on_complete(self):
        for indicator in self.domains_re:
            for domain in self.check_domain(pattern=indicator, regex=True, all=True):
                self.mark_ioc("domain", domain)

        return self.has_marks()
