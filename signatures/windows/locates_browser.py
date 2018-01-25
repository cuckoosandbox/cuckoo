# Copyright (C) 2010-2015 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class LocatesBrowser(Signature):
    name = "locates_browser"
    description = "Tries to locate where the browsers are installed"
    severity = 1
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    files_re = [
        "C:\\\\Program\\ Files(\\ \\(x86\\))?\\\\Google\\\\Chrome\\\\Application",
        "C:\\\\Program\\ Files(\\ \\(x86\\))?\\\\Mozilla\\ Firefox",
    ]

    regkeys_re = [
        ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\Google Chrome",
        ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\App\\ Paths\\\\chrome.exe",
        ".*\\\\Mozilla\\\\Mozilla\\ Firefox",
        ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\App\\ Paths\\\\firefox.exe",
    ]

    def on_complete(self):
        for indicator in self.files_re:
            filepath = self.check_file(pattern=indicator, regex=True)
            if filepath:
                self.mark_ioc("file", filepath)

        for indicator in self.regkeys_re:
            regkey = self.check_key(pattern=indicator, regex=True)
            if regkey:
                self.mark_ioc("registry", regkey)

        return self.has_marks()
