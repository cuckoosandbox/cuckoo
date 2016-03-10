# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class TinbaMutexes(Signature):
    name = "banker_tinba_mutexes"
    description = "Creates known Tinba Banking Trojan mutexes"
    severity = 3
    categories = ["rat"]
    families = ["tinba"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*98227AC9",
        ".*CD7A76F4",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            if self.check_mutex(pattern=indicator, regex=True):
                return True

        return False
