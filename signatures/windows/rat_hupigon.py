# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Hupigon(Signature):
    name = "rat_hupigon"
    description = "Creates known Hupigon files, registry keys and/or mutexes"
    severity = 3
    categories = ["rat"]
    families = ["hupigon"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*Hacker\\.com\\.cn",
        ".*com\\.cn.*MUTEX",
        ".*xERONETWO",
        ".*GZVER",
        ".*HgzVip",
        ".*kjshsu234",
        ".*BBBBBBe",
        ".*VERONET",
        ".*RAV2"
    ]

    files_re = [
        ".*rejoic",
        ".*MSINFO.*QQMin\\.exe",
        ".*FieleWay\\.txt",
        ".*DelFile.*\\.txt",
        ".*qqq\\.exe",
        ".*DelSuep",
        ".*SetupWay",
        ".*bootstat\\.dat",
        ".*Hacker\\.com\\.cn\\.exe",
        ".*MSInfo.*2010\\.txt",
        ".*MSInfo.*Adobe\\.exe",
        ".*Temp.*pstgdump.*exe",
        ".*Temp.*servpw64.*exe",
    ]

    regkeys_re = [
        ".*rejoice2008",
        ".*Services.*National",
        ".*Services.*NapAgent.*Shas.*UI",
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
