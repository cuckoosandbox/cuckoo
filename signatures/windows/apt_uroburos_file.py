# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class UroburosFile(Signature):
    name = "uroburos_file"
    description = "Creates known Turla/Uroburos APT files"
    severity = 3
    categories = ["rat"]
    families = ["uroburos"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*turla10",
        ".*msdata\\\\.*",
        ".*1396695624",
    ]

    def on_complete(self):
        for mutex in self.mutexes_re:
            if self.check_mutex(pattern=mutex):
                return True
