# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class TrojanRedosru(Signature):
    name = "trojan_redosru"
    description = "Creates known Redosru Trojan Files, Registry Keys and/or Mutexes"
    severity = 3
    categories = ["trojan"]
    families = ["redosru"]
    authors = ["RedSocks"]
    minimum = "2.0"

    files_re = [
        ".*NetSyste81.*dll",
    ]

    mutexes_re = [
        ".*8456",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            mutex = self.check_mutex(pattern=indicator, regex=True)
            if mutex:
                self.mark_ioc("mutex", mutex)

        for indicator in self.files_re:
            regkey = self.check_file(pattern=indicator, regex=True)
            if regkey:
                self.mark_ioc("file", regkey)

        return self.has_marks()
