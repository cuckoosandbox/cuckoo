# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DisableCmd(Signature):
    name = "locker_cmd"
    description = "Disables Windows' cmd.exe"
    severity = 2
    categories = ["locker"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    indicator = ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion" \
        "\\\\Policies\\\\System\\DisableCmd$"

    def on_complete(self):
        for regkey in self.check_key(pattern=self.indicator, regex=True, actions=["regkey_written"], all=True):
            self.mark_ioc("registry", regkey)

        return self.has_marks()
