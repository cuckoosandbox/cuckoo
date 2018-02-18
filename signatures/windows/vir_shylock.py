# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Shylock(Signature):
    name = "shylock"
    description = "Creates known Caphaw/Shylock files, registry keys and/or mutexes"
    severity = 3
    categories = ["rat"]
    families = ["shylock"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*5933CD81FC25AAC7F38AA72198587A4059335933CD81",
        ".*A3905BF548209259991D789F366C197BA3A3905BF5",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            mutex = self.check_mutex(pattern=indicator, regex=True)
            if mutex:
                self.mark_ioc("mutex", mutex)

        return self.has_marks()
