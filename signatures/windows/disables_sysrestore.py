# Copyright (C) 2015 Kevin Ross, Updated 2016 For Cuckoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class DisablesSystemRestore(Signature):
    name = "disables_system_restore"
    description = "Attempts to disable System Restore"
    severity = 3
    categories = ["ransomware", "persistance"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    regkeys_re = [
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\SystemRestore\\\\DisableSR$",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Policies\\\\Microsoft\\\\Windows\\ NT\\\\SystemRestore\\\\DisableSR$",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Policies\\\\Microsoft\\\\Windows\\ NT\\\\SystemRestore\\\\DisableConfig$",
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            for regkey in self.check_key(pattern=indicator, regex=True, actions=["regkey_written"], all=True):
                self.mark_ioc("registry", regkey)

        return self.has_marks()
