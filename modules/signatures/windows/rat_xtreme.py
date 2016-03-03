# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class XtremeRAT(Signature):
    name = "rat_xtreme"
    description = "Creates known XtremeRAT files, registry keys or mutexes"
    severity = 3
    categories = ["rat"]
    families = ["xtremerat"]
    authors = ["RedSocks"]
    minimum = "2.0"

    references = [
        "https://malwr.com/analysis/ODVlOWEyNDU3NzBhNDE3OWJkZjE0ZjIxNTdiMzU1YmM/",
        "https://malwr.com/analysis/ZWM4YjI2MzI1MmQ2NDBkMjkwNzI3NzhjNWM5Y2FhY2U/",
        "https://malwr.com/analysis/MWY5YTAwZWI1NDc3NDJmMTgyNDA4ODc0NTk0MWIzNjM/",
    ]

    mutexes_re = [
        ".*XTREMEUPDATE",
        ".*XTREMEPERSIST",
        ".*XTREMECLIENT",
        ".*Xtreme",
        "Xtreme.*RAT.*Private",
        ".*\\(\\(Mutex\\)\\)",
    ]

    regkeys_re = [
        ".*\\\\SOFTWARE\\\\XtremeRAT",
        ".*\\\\SOFTWARE\\\\YdymVYB73",
    ]

    files_re = [
        ".*Xtreme.*RAT.*",
        ".*Xtreme.*Private",
        ".*xtreme.*private.*fixed.*",
        ".*Application.*Microsoft.*Windows.*xtr",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            match = self.check_mutex(pattern=indicator)
            if match:
                self.mark_ioc("mutex", match)

        for indicator in self.regkeys_re:
            match = self.check_key(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("regkey", match)

        for indicator in self.files_re:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("file", match)

        return self.has_marks()
