# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Plugx(Signature):
    name = "rat_plugx"
    description = "Creates known PlugX files, registry keys and/or mutexes"
    severity = 3
    categories = ["rat"]
    families = ["plugx"]
    authors = ["threatlead", "nex", "RedSocks"]
    minimum = "2.0"

    references = [
        "https://malwr.com/analysis/YTZjYmUwMzNlNzkwNGU5YmIxNDQwYTcyYjFkYWI0NWE/",
    ]

    mutexes_re = [
        ".*DoInstPrepare",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            mutex = self.check_mutex(pattern=indicator, regex=True)
            if mutex:
                self.mark_ioc("mutex", mutex)

        return self.has_marks()
