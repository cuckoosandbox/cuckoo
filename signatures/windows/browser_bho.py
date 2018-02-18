# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class InstallsBHO(Signature):
    name = "installs_bho"
    description = "Installs a Browser Helper Object to thwart the users browsing experience"
    severity = 3
    categories = ["browser"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    regkeys_re = [
        ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Browser\\ Helper\\ Objects",
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            for regkey in self.check_key(pattern=indicator, actions=["regkey_written"], regex=True, all=True):
                self.mark_ioc("bho_regkey", regkey)
        return self.has_marks()
