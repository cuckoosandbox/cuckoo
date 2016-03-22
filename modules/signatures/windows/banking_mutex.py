# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class BankingMutexes(Signature):
    name = "banking_mutexes"
    description = "Creates known Online Banking mutexes"
    severity = 3
    categories = ["banking"]
    families = ["applications"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*CCB Online e-Bank HDZB",
        ".*CCB-E Setup Mutex",
        ".*ForexNetBankAppMutex",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            if self.check_mutex(pattern=indicator):
                return True
