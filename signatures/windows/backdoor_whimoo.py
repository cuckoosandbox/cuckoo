# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Whimoo(Signature):
    name = "backdoor_whimoo"
    description = "Creates known Schwarzesonne Backdoor files, registry keys and/or mutexes"
    severity = 3
    categories = ["backdoor"]
    families = ["whimoo"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        "xDsX980",
        "Slayer.*PERS",
        "Slayer.*KILL",
    ]

    files_re = [
        "C:\\\\WINDOWS\\\\(system32|syswow64)\\\\melt\\.bat",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            if self.check_mutex(pattern=indicator, regex=True):
                return True

        for indicator in self.files_re:
            if self.check_file(pattern=indicator, regex=True):
                return True
