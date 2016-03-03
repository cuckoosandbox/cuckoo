# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Vanbot(Signature):
    name = "backdoor_vanbot"
    description = "Creates known Vanbot Backdoor files, registry keys and/or mutexes"
    severity = 3
    categories = ["backdoor"]
    families = ["vanbot"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*rx-asn-2-re-worked"
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            if self.check_mutex(pattern=indicator):
                return True
