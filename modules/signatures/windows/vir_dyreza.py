# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Dyreza(Signature):
    name = "dyreza"
    description = "Creates known Dyreza Banking Trojan files, registry keys and/or mutexes"
    severity = 3
    categories = ["banking"]
    families = ["dyreza"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*Rangismutex5",
        ".*Diper89",
        ".*Xider78",
        ".*zx5fwtw4ep",
    ]

    files_re = [
        ".*Temp.*fax.*scr",
        ".*Temp.*mmo.*txt",
        ".*tubeini.*exe",
        ".*mfcsubs.dll",
        ".*Temp.*mscodecs.exe",
        ".*system32.*Duser.*dll",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            mutex = self.check_mutex(pattern=indicator, regex=True)
            if mutex:
                self.mark_ioc("mutex", mutex)

        for indicator in self.files_re:
            regkey = self.check_file(pattern=indicator, regex=True)
            if regkey:
                self.mark_ioc("file", regkey)

        return self.has_marks()
