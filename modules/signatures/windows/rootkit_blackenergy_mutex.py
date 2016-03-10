# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class BlackEnergyMutexes(Signature):
    name = "blackenergy_mutexes"
    description = "Creates known BlackEnergy Rootkit mutexes"
    severity = 3
    categories = ["rootkit"]
    families = ["blackenergy"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*\\{CD56173D-1A7D-4E99-8109-A71BB04263DF\\}",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            match = self.check_mutex(pattern=indicator)
            if match:
                self.mark_ioc("mutex", match)

        return self.has_marks()
