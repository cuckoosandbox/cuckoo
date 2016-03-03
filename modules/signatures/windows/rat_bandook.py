# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Bandook(Signature):
    name = "bandook"
    description = "Creates known Bandook files and/or mutexes"
    severity = 3
    categories = ["rat"]
    families = ["bandook"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*onepointthreefour",
        ".*sexage2007",
        ".*yYaFNapAeNN0hk6wcwc",
    ]

    files_re = [
        ".*bandook",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            match = self.check_mutex(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("mutex", match)

        for indicator in self.files_re:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("file", match)

        return self.has_marks()
