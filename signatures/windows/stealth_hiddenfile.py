# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com), Updated 2016 For Cuckoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class StealthHiddenFile(Signature):
    name = "stealth_hiddenfile"
    description = "Attempts to modify Explorer settings to prevent hidden files from being displayed"
    severity = 3
    categories = ["stealth"]
    authors = ["Optiv"]
    minimum = "2.0"

    regkeys_re = [
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Advanced\\\\Hidden$",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Advanced\\\\ShowSuperHidden$",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Advanced\\\\SuperHidden$",
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            for regkey in self.check_key(pattern=indicator, regex=True, actions=["regkey_written"], all=True):
                self.mark_ioc("registry", regkey)

        return self.has_marks()
