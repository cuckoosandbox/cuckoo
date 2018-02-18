# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Flystudio(Signature):
    name = "rat_flystudio"
    description = "Creates known FlyStudio files, registry keys and/or mutexes"
    severity = 3
    categories = ["rat"]
    families = ["flystudio"]
    authors = ["RedSocks"]
    minimum = "2.0"

    regkeys_re = [
        ".*FlySky.*"
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            match = self.check_key(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("regkey", match)

        return self.has_marks()
