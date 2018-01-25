# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Renocide(Signature):
    name = "worm_renocide"
    description = "Creates known Renocide Worm files, registry keys and/or mutexes"
    severity = 3
    categories = ["worm"]
    families = ["renocide"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*df8g1sdf68g18er1g8re16",
    ]

    files_re = [
        ".*95a1sd\\.xx",
        ".*\\\\Temp\\\\nrrtrvm",
        ".*\\\\Temp\\\\aut1\\.tmp",
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
