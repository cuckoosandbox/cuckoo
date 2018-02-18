# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com), Updated 2016 for Cuckoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DisablesWindowsUpdate(Signature):
    name = "disables_windowsupdate"
    description = "Attempts to disable Windows Auto Updates"
    severity = 3
    categories = ["generic"]
    authors = ["Optiv"]
    minimum = "2.0"

    regkeys_re = [
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Policies\\\\Microsoft\\\\Windows\\\\WindowsUpdate\\\\(AU\\\\NoAutoUpdate|Auto\\ Update\\\\AUOptions)$",
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            for regkey in self.check_key(pattern=indicator, regex=True, actions=["regkey_written"], all=True):
                self.mark_ioc("registry", regkey)

        return self.has_marks()
