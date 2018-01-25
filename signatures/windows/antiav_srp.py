# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com), Updated 2016 for cuckoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AntiAVSRP(Signature):
    name = "antiav_srp"
    description = "Modifies Software Restriction Policies likely to cripple AV"
    severity = 3
    categories = ["anti-av"]
    authors = ["Optiv"]
    minimum = "2.0"

    regkeys_re = [
        ".*\\\\Policies\\\\Microsoft\\\\Windows\\\\Safer\\\\\CodeIdentifiers\\\\0\\\\Paths\\\\.*",
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            for regkey in self.check_key(pattern=indicator, regex=True, actions=["regkey_written"], all=True):
                self.mark_ioc("registry", regkey)

        return self.has_marks()
