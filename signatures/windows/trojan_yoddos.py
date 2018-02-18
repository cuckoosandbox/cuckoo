# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class trojanyoddos(Signature):
    name = "trojan_yoddos"
    description = "Creates known YoDDoS Trojan files, registry keys and/or mutexes"
    severity = 3
    categories = ["trojan"]
    families = ["yoddos"]
    authors = ["RedSocks"]
    minimum = "2.0"

    regkeys_re = [
        ".*\\\\Services\\\\XillAlluxl\\ web\\ Service",
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            regkey = self.check_key(pattern=indicator, regex=True)
            if regkey:
                self.mark_ioc("registry", regkey)

        return self.has_marks()
