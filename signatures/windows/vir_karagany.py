# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Karagany(Signature):
    name = "karagany"
    description = "Creates known Karagany files, registry keys and/or mutexes (Havex APT)"
    severity = 3
    categories = ["rat"]
    families = ["karagany"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*yUo9Ck1Io",
        ".*hed334d3d",
    ]

    regkeys_re = [
        "HKEY_CLASSES_ROOT\\\\ljoiu",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            mutex = self.check_mutex(pattern=indicator, regex=True)
            if mutex:
                self.mark_ioc("mutex", mutex)

        for indicator in self.regkeys_re:
            regkey = self.check_key(pattern=indicator, regex=True)
            if regkey:
                self.mark_ioc("registry", regkey)

        return self.has_marks()
