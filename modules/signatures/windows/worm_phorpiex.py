# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Phorpiex(Signature):
    name = "worm_phorpiex"
    description = "Creates known Phorphiex files, registry keys and/or mutexes"
    severity = 3
    categories = ["worm"]
    families = ["phorpiex"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*r3tq4tqz4qz4tq4",
        ".*57f6g9807e657fg879h8",
        ".*68d57sd56f87d6s75df6",
        ".*h7d6f79d57d7f6dg4h",
        ".*tbot6",
        ".*spm3",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            mutex = self.check_mutex(pattern=indicator, regex=True)
            if mutex:
                self.mark_ioc("mutex", mutex)

        return self.has_marks()
