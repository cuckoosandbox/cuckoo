# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Blackshades(Signature):
    name = "rat_blackshades"
    description = "Creates known Blackshades files, registry keys and/or mutexes"
    severity = 3
    categories = ["rat"]
    families = ["blackshades"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*5YC7O85PVT",
        ".*LSSQ2Z3MFX",
        ".*806IO5VL40",
        ".*W6R2IW0RYY",
        ".*KVX7X8Y8S5",
        ".*I29N3SV95O",
    ]

    files_re = [
        ".*BlackShades",
    ]

    regkeys_re = [
        ".*BlackShades",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            match = self.check_mutex(pattern=indicator)
            if match:
                self.mark_ioc("mutex", indicator)

        for indicator in self.files_re:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("file", indicator)

        for indicator in self.regkeys_re:
            match = self.check_key(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("regkey", match)

        return self.has_marks()
