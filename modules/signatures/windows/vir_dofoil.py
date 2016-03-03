# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DoFoil(Signature):
    name = "dofoil"
    description = "Creates known DoFoil files, registry keys and/or mutexes"
    severity = 3
    categories = ["virus"]
    families = ["dofoil"]
    authors = ["RedSocks"]
    minimum = "2.0"

    regkeys_re = [
        ".*dofoil",
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            regkey = self.check_key(pattern=indicator, regex=True)
            if regkey:
                self.mark_ioc("registry", regkey)

        return self.has_marks()
