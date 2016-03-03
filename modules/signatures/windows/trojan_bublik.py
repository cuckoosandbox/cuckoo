# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Bublik(Signature):
    name = "trojan_bublik"
    description = "Creates known Bublik Trojan files, registry keys and/or mutexes"
    severity = 3
    categories = ["rat"]
    families = ["bublik"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*V8x",
        ".*muipcdraotse",
        ".*rbulnanbilnag",
    ]

    regkeys_re = [
        ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Advanced\\\\Folder\\\\SuperHidden",
    ]

    files_re = [
        "C:\\\\WINDOWS\\\\(system32|syswow64)\\\\wmpsl64.exe",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            mutex = self.check_mutex(pattern=indicator, regex=True)
            if mutex:
                self.mark_ioc("mutex", mutex)

        for indicator in self.regkeys_re:
            regkey = self.check_key(pattern=indicator, regex=True)
            if regkey:
                self.mark_ioc("registry", regkey)

        for indicator in self.files_re:
            regkey = self.check_file(pattern=indicator, regex=True)
            if regkey:
                self.mark_ioc("file", regkey)

        return self.has_marks()
