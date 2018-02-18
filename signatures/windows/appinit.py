# Copyright (C) 2010-2015 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class InstallsAppInit(Signature):
    name = "installs_appinit"
    description = "Installs itself in AppInit to inject into new processes"
    severity = 3
    categories = ["persistence"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    regkeys_re = [
        ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Windows\\\\Appinit_Dlls",
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            regkey = self.check_key(pattern=indicator, regex=True, actions=["regkey_written"])
            if regkey:
                self.mark_ioc("registry", regkey)

        return self.has_marks()
