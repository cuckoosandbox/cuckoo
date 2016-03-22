# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Bifrose(Signature):
    name = "rat_bifrose"
    description = "Creates known Bifrose files, registry keys and/or mutexes"
    severity = 3
    categories = ["rat"]
    families = ["bifrose"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*Bif123",
        ".*Bif1234",
        ".*TENTENK",
        ".*Slayer616URE",
        ".*Slayer616URE_KILL",
        ".*Slayer616URE_PERS",
        ".*93nf3",
        ".*weas",
        ".*dbeWd",
        ".*stb",
    ]

    regkeys_re = [
        ".*\\\\SOFTWARE\\\Bifrost",
        ".*\\\\SOFTWARE\\\SiLeNtt",
    ]

    files_re = [
        ".*Bifrost",
        ".*WINDOWS.*plugin1.*dat",
        ".*WINDOWS.*lsass2.*exe",
        ".*WINDOWS.*system32.*SiLeNtt",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            match = self.check_mutex(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("mutex", match)

        for indicator in self.regkeys_re:
            match = self.check_key(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("regkey", match)

        for indicator in self.files_re:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("file", match)

        return self.has_marks()
