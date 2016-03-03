# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DropBox(Signature):
    name = "cloud_dropbox"
    description = "Looks up the Dropbox cloud service"
    severity = 2
    categories = ["cloud"]
    authors = ["RedSocks"]
    minimum = "2.0"

    domains = [
        "dropbox.com",
        "www.dropbox.com",
        "dl.dropboxusercontent.com",
        "dl.dropbox.com",
        "dl-balancer.x.dropbox.com",
        "www.v.dropbox.com",
        "duc-balancer.x.dropbox.com",
    ]

    def on_complete(self):
        for indicator in self.domains:
            if self.check_domain(pattern=indicator):
                self.mark_ioc("domain", indicator)
                return True
