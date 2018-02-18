# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Napolar(Signature):
    name = "vir_napolar"
    description = "Creates known Napolar files, registry keys and/or mutexes"
    severity = 3
    categories = ["vir"]
    families = ["napolar"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*gcc-shmem-tdm2-use_fc_key",
        ".*gcc-shmem-tdm2-sjlj_once",
        ".*gcc-shmem-tdm2-fc_key",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            match = self.check_mutex(pattern=indicator)
            if match:
                self.mark_ioc("mutex", match)

        return self.has_marks()
