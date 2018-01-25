# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class VNLoaderURL(Signature):
    name = "bot_vnloader_url"
    description = "Contacts C&C server HTTP check-in (VNLoader HTTP Bot)"
    severity = 3
    categories = ["bot"]
    authors = ["RedSocks"]
    minimum = "2.0"

    urls_re = [
        ".*/vnLoader",
    ]

    def on_complete(self):
        for indicator in self.urls_re:
            match = self.check_url(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("url", match)
                return True
