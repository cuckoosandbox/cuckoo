# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class apt_sandworm_url(Signature):
    name = "apt_sandworm_url"
    description = "Uses Known Sandworm APT URL Indicator"
    severity = 2
    categories = ["apt"]
    authors = ["RedSocks"]
    minimum = "2.0"

    urls_re = [
        ".*YXJyYWtpczAy.*",
        ".*aG91c2VhdHJlaWRlczk0.*",
        ".*\/loadvers\/paramctrl\.php",
        ".*\/dirconf\/check\.php",
        ".*\/siteproperties\/viewframes\/dialog\.php",
    ]

    def on_complete(self):
        for url in self.urls_re:
            if self.check_url(pattern=url, regex=True):
                self.mark_ioc("url", url)

        return self.has_marks()
