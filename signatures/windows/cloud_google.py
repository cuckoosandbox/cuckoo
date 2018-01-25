# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class CloudGoogle(Signature):
    name = "cloud_google"
    description = "Looks up documents from one of Google's services"
    severity = 2
    categories = ["cloud"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    domains = [
        "docs.google.com",
        "drive.google.com",
    ]

    def on_complete(self):
        for indicator in self.domains:
            if self.check_domain(pattern=indicator):
                self.mark_ioc("domain", indicator)

        return self.has_marks()
