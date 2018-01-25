# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com), Updated 2016 for cuckoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class IMStealer(Signature):
    name = "infostealer_im"
    description = "Harvests information related to installed instant messenger clients"
    severity = 3
    categories = ["infostealer"]
    authors = ["Optiv"]
    minimum = "2.0"

    file_indicators = [
         ".*\\\\AIM\\\\aimx\.bin$",
         ".*\\\\Digsby\\\\loginfo\.yaml$",
         ".*\\\\Digsby\\\\Digsby\.dat$",
         ".*\\\\Meebo\\\\MeeboAccounts\.txt$",
         ".*\\\\Miranda\\\\.*\.dat$",
         ".*\\\\MySpace\\\\IM\\\\users\.txt$",
         ".*\\\\\.purple\\\\Accounts\.xml$",
         ".*\\\\Application\\ Data\\\\Miranda\\\\.*",
         ".*\\\\AppData\\\\Roaming\\\\Miranda\\\\.*",
         ".*\\\\Skype\\\\.*\\\\config\.xml$",
         ".*\\\\Tencent\\ Files\\\\.*\\\\QQ\\\\Registry\.db$",
         ".*\\\\Trillian\\\\users\\\\global\\\\accounts\.ini$",
         ".*\\\\Xfire\\\\XfireUser\.ini$"
    ]

    reg_indicators = [
         ".*\\\\Software\\\\(Wow6432Node\\\\)?America\\ Online\\\\AIM6\\\\Passwords.*",
         ".*\\\\Software\\\\(Wow6432Node\\\\)?AIM\\\\AIMPRO\\\\.*",
         ".*\\\\Software\\\\(Wow6432Node\\\\)?Beyluxe\\ Messenger\\\\.*",
         ".*\\\\Software\\\\(Wow6432Node\\\\)?BigAntSoft\\\\BigAntMessenger\\\\.*",
         ".*\\\\Software\\\\(Wow6432Node\\\\)?Camfrog\\\\Client\\\\.*",
         ".*\\\\Software\\\\(Wow6432Node\\\\)?Google\\\\Google\\ Talk\\\\Accounts.*",
         ".*\\\\Software\\\\(Wow6432Node\\\\)?IMVU\\\\.*",
         ".*\\\\Software\\\\(Wow6432Node\\\\)?Nimbuzz\\\\PCClient\\\\Application\\\\.*",
         ".*\\\\Software\\\\(Wow6432Node\\\\)?Paltalk.*",
         ".*\\\\Software\\\\(Wow6432Node\\\\)?Yahoo\\\\Pager\\\\.*"
    ]

    def on_complete(self):
        for indicator in self.file_indicators:
            for match in self.check_file(pattern=indicator, regex=True, all=True):
                self.mark_ioc("file", match)

        for indicator in self.reg_indicators:
            for regkey in self.check_key(pattern=indicator, regex=True, all=True):
                self.mark_ioc("registry", regkey)

        return self.has_marks()
