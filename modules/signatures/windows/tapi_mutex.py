# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class TapiDpMutexes(Signature):
    name = "TAPI_DP_mutex"
    description = "Creates known TAPI mutex, possibly intended for Toll Fraud"
    severity = 3
    categories = ["fraud"]
    families = ["tapi"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*tapi_dp_mutex",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            match = self.check_mutex(pattern=indicator)
            if match:
                self.mark_ioc("mutex", match)

        return self.has_marks()
