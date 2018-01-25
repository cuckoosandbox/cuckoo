# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Psyokym(Signature):
    name = "worm_psyokym"
    description = "Creates known Psyokym Worm files, registry keys and/or mutexes"
    severity = 3
    categories = ["worm"]
    families = ["psyokym"]
    authors = ["RedSocks"]
    minimum = "2.0"

    files_re = [
        ".*habeys.*exe",
    ]

    def on_complete(self):
        for indicator in self.files_re:
            regkey = self.check_file(pattern=indicator, regex=True)
            if regkey:
                self.mark_ioc("file", regkey)

        return self.has_marks()
