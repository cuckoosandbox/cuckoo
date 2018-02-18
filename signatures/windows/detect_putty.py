# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Putty(Signature):
    name = "detect_putty"
    description = "Putty Files, Registry Keys and/or Mutexes Detected"
    severity = 3
    categories = ["ssh"]
    families = ["putty"]
    authors = ["RedSocks"]
    minimum = "2.0"

    files_re = [
        ".*putty",
    ]

    def on_complete(self):
        for indicator in self.files_re:
            if self.check_file(pattern=indicator, regex=True):
                return True
