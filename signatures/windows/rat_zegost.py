# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Zegost(Signature):
    name = "rat_zegost"
    description = "Creates known Zegost files, registry changes and/or mutexes"
    severity = 3
    categories = ["rat"]
    families = ["zegost"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*VVVVVVrr2unw",
        ".*MC9fYAAvC",
        ".*AAAAAA",
    ]

    regkeys_re = [
        ".*\\\\sOFtwaRe\\\\jddnwupve",
        ".*\\\\sOFtwaRe\\\\jddnwupveo",
    ]

    files_re = [
        "C:\\\\WINDOWS\\\\temp\\\\zk.exe",
        "C:\\\\Windows\\\\temp\\\\2011.exe",
        "c:\\\\Windows\\\\BJ.exe",
        "c:\\\\Windows\\\\svchest12700.exe",
        "C:\\\\Program\\ Files\\\\Common\\ Files\\\\loveuu.bat",
        "C:\\\\Program\\ Files\\\\Common\\ Files\\\\loveuu.png",
        "C:\\\\WINDOWS\\\\system32\\\\da130f3a.rdb",
        "C:\\\\WINDOWS\\\\system32\\\\3A3FF008",
        "C:\\\\WINDOWS\\\\FuckYou.reg",
        "C:\\\\WINDOWS\\\\FuckYou.txt",
        "C:\\\\WINDOWS\\\\system32\\\\da130f3a.rdb"
        ".*\\\\temp\\\\mhoyxxhdub.dat",
        ".*mkfcxlbgu",
        ".*cfwchcuycw",
        ".*cqykyqwtyq",
        ".*jddnwupve",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            match = self.check_mutex(pattern=indicator)
            if match:
                self.mark_ioc("mutex", match)

        for indicator in self.regkeys_re:
            match = self.check_key(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("regkey", match)

        for indicator in self.files_re:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("file", match)

        return self.has_marks()
