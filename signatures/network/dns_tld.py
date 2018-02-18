# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Suspicious_TLD(Signature):
    name = "suspicious_tld"
    description = "Resolves a suspicious Top Level Domain (TLD)"
    severity = 2
    categories = ["tldwatch", "network"]
    authors = ["RedSocks", "Kevin Ross"]
    minimum = "2.0"

    domains_re = [
        (".*\\.by$", "Belarus domain TLD"),
        (".*\\.cc$", "Cocos Islands domain TLD"),
        (".*\\.onion$", "TOR hidden services domain TLD"),
        (".*\\.pw$", "Palau domain TLD"),
        (".*\\.ru$", "Russian Federation domain TLD"),
        (".*\\.su$", "Soviet Union domain TLD"),
        (".*\\.top$", "Generic top level domain TLD"),
    ]
    queried_domains = []

    def on_complete(self):
        for indicator in self.domains_re:
            for tld in self.check_domain(pattern=indicator[0], regex=True, all=True):
                if tld not in self.queried_domains:
                    self.queried_domains.append(tld)
                    self.mark(
                        domain=tld,
                        description=indicator[1],
                    )

        return self.has_marks()
