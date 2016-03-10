# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class JintorMutexes(Signature):
    name = "jintor_mutexes"
    description = "Creates known Jintor Keylogger mutexes"
    severity = 3
    categories = ["keylogger"]
    families = ["jintor"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*766bb4b86c4da19fca562819fb7b8a18",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            match = self.check_mutex(pattern=indicator)
            if match:
                self.mark_ioc("mutex", match)

        return self.has_marks()
