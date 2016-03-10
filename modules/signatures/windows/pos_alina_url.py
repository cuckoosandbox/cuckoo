# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AlineURL(Signature):
    name = "alina_pos_url"
    description = "Contacts C&C server HTTP check-in (Alina Point of Sale Malware)"
    severity = 3
    categories = ["pos"]
    authors = ["RedSocks"]
    minimum = "2.0"

    urls_re = [
        ".*grabbedinfo7sob7.*",
        ".*forum.*admin.*php",
        ".*insid.*admin.*php",
    ]

    def on_complete(self):
        for indicator in self.urls_re:
            match = self.check_url(pattern=indicator, regex=True)
            if match:
                self.data.append({"url": match})
                return True
