# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class MailStealer(Signature):
    name = "infostealer_mail"
    description = "Harvests credentials from local email clients"
    severity = 3
    categories = ["infostealer"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    regkeys_re = [
        ".*\\\\Software\\\\IncrediMail",
        ".*\\\\RIT\\\\The\\ Bat\\!",
        ".*\\\\Microsoft\\\\Internet\\ Account\\ Manager\\\\Accounts",
        ".*\\\\Software\\\\Microsoft\\\\Windows\\ Mail",
        ".*\\\\Software\\\\Microsoft\\\\Windows\\ Live\\ Mail",
        ".*\\\\Software\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Windows\\ Messaging\\ Subsystem",
        ".*\\\\Software\\\\Microsoft\\\\Internet\\ Account\\ Manager",
        ".*\\\\Software\\\\Microsoft\\\\Office\\\\Outlook\\\\OMI\\ Account\\ Manager",
        ".*\\\\Software\\\\RimArts\\\\B2\\\\Settings",
        ".*\\\\Software\\\\Poco\\ Systems\\ Inc",
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            registry = self.check_key(pattern=indicator, regex=True)
            if registry:
                self.mark_ioc("registry", registry)

        return self.has_marks()
