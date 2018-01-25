# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Dns_Freehosting_Domain(Signature):
    name = "dns_freehosting_domain"
    description = "Resolves Free Hosting Domain, Possibly Malicious"
    severity = 2
    categories = ["freehosting"]
    authors = ["RedSocks"]
    minimum = "2.0"

    domains_re = [
        ".*\.yzi\.me",
        ".*\.hol\.es",
        ".*\.zxq\.net",
        ".*\.ta4a\.info",
        ".*\.url\.ph",
        ".*\.vacau\.com",
        ".*\.netai\.net",
        ".*\.webege\.com",
        ".*\.6te\.net",
        ".*\.meximas\.com",
        ".*\.ws\.gy",
        ".*\.comuv\.com",
        ".*\.comuf\.com",
        ".*\.comze\.com",
        ".*\.comoj\.com",
        ".*\.favcc1\.com",
        ".*\.y55\.eu",
        ".*\.esy\.es",
        ".*\.pixub\.com",
        ".*\.1x\.biz",
        ".*\.altervista\.org",
        ".*\.website\.org",
        ".*\.net84\.net",
        ".*\.besaba\.com",
        ".*\.5gbfree\.com",
        ".*\.site40\.net",
        ".*\.site50\.net",
        ".*\.site88\.net",
        ".*\.comxa\.com",
        ".*\.site11\.com",
        ".*\.host22\.com",
        ".*\.000a\.de",
        ".*\.freeiz\.com",
        ".*\.net23\.net",
        ".*\.net46\.net",
        ".*\.cwsurf\.de",
        ".*\.uni\.me",
        ".*\.look\.in",
        ".*\.comule\.com",
        ".*\.comeze\.com",
        ".*\.x10host\.com",
    ]

    def on_complete(self):
        for indicator in self.domains_re:
            match = self.check_domain(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("domain", match)

        return self.has_marks()
