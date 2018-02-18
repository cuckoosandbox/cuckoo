# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Rovnix(Signature):
    name = "rovnix"
    description = "Rovnix Trojan"
    severity = 3
    categories = ["banker", "trojan"]
    authors = ["Mikael Keri"]
    minimum = "2.0"

    files_re = [
        ".*\\\\AppData\\\\Local\\\\Temp\\\\L[0-9]{9}",
        ".*\\\\AppData\\\\Roaming\\\\Microsoft\\\\Crypto\\\\RSA\\\\RSA[0-9]{9}.dll",
        ".*\\\\AppData\\\\Roaming\\\\Microsoft\\\\Crypto\\\\RSA\\\\KEYS\\\\CFG[0-9]{9}.dll",
        ".*\\\\AppData\\\\Roaming\\\\Microsoft\\\\Crypto\\\\RSA\\\\KEYS\\\\DB[0-9]{9}.dll",
    ]

    regkeys_re = [
        ".*\\\\Software\\\\Microsoft\\\\Installer\\\\Products\\\\B[0-9]{9}",
    ]

    mutexes_re = [
        ".*UACNTFS[0-9]{9}",
        ".*INSNTFS[0-9]{9}",
        ".*BDNTFS[0-9]{9}",
        ".*PL6NTFS[0-9]{9}",
        ".*PL1NTFS[0-9]{9}",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            for mutex in self.check_mutex(pattern=indicator, regex=True, all=True):
                self.mark_ioc("mutex", mutex)

        for indicator in self.regkeys_re:
            for regkey in self.check_key(pattern=indicator, regex=True, all=True):
                self.mark_ioc("registry", regkey)

        for indicator in self.files_re:
            for regkey in self.check_file(pattern=indicator, regex=True, all=True):
                self.mark_ioc("file", regkey)

        return self.has_marks()
