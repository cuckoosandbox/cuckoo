# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Beastdoor(Signature):
    name = "rat_beastdoor"
    description = "Creates known BeastDoor files, registry keys and/or mutexes"
    severity = 3
    categories = ["rat"]
    families = ["beastdoor"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*Bst_run",
    ]

    regkeys_re = [
        ".*mspgcs",
    ]

    files_re = [
        ".*dxdgns",
        ".*mspgcs",
        ".*msdqwn",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            match = self.check_mutex(pattern=indicator)
            if match:
                self.mark_ioc("mutex", match)

        for indicator in self.regkeys_re:
            match = self.check_key(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("regkey", match)

        for indicator in self.files_re:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("file", match)

        return self.has_marks()
