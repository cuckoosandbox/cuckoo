# Copyright (C) 2015 Kevin Ross, Optiv, Inc. (brad.spengler@optiv.com), Updated 2016 for Cuckoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class ModifySecurityCenterWarnings(Signature):
    name = "modifies_security_center_warnings"
    description = "modify_security_center_warnings"
    severity = 3
    categories = ["stealth"]
    authors = ["Kevin Ross", "Optiv"]
    minimum = "2.0"

    regkeys_re = [
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Security\\ Center\\\\.*",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\explorer\\\\ShellServiceObjects\\\\{FD6905CE-952F-41F1-9A6F-135D9C6622CC}$",
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            for regkey in self.check_key(pattern=indicator, regex=True, actions=["regkey_written"], all=True):
                self.mark_ioc("registry", regkey)

        return self.has_marks()
