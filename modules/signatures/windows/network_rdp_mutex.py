# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class RdpMutexes(Signature):
    name = "rdp_mutexes"
    description = "Creates Remote Desktop Protocol (RDP) Mutexes"
    severity = 3
    categories = ["rat"]
    families = ["rdp"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        "msrdp*",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            match = self.check_mutex(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("mutex", match)

        return self.has_marks()
