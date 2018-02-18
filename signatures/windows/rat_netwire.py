# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Netwire(Signature):
    name = "netwire"
    description = "Creates known Netwire files, registry keys and/or mutexes"
    severity = 3
    categories = ["rat"]
    families = ["netwire"]
    authors = ["RedSocks"]
    minimum = "2.0"

    regkeys = [
        "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\NetWire",
    ]

    def on_complete(self):
        for key in self.regkeys:
            match = self.check_key(pattern=key)
            if match:
                self.mark_ioc("regkey", match)

        return self.has_marks()
