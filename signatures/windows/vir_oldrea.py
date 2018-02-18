# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Oldrea(Signature):
    name = "oldrea"
    description = "Creates known Oldrea files, registry keys and/or mutexes (Havex APT)"
    severity = 3
    categories = ["rat"]
    families = ["oldrea"]
    authors = ["RedSocks"]
    minimum = "2.0"

    files_re = [
        ".*\\\\Temp\\\\qln\\.dbx",
    ]

    def on_complete(self):
        for indicator in self.files_re:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("file", match)

        return self.has_marks()
