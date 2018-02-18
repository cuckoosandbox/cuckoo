# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com), Kevin Ross, Updated 2016 for Cuckoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DisablesBrowserWarn(Signature):
    name = "disables_browser_warn"
    description = "Attempts to disable browser security warnings"
    severity = 3
    categories = ["generic", "banker", "clickfraud"]
    authors = ["Optiv", "Kevin Ross"]
    minimum = "2.0"

    regkeys_re = [
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet\\ Settings\\\\WarnOnBadCertRecving",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet\\ Settings\\\\WarnOnBadCertSending",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet\\ Settings\\\\WarnOnHTTPSToHTTPRedirect",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet\\ Settings\\\\WarnOnZoneCrossing",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet\\ Settings\\\\WarnOnPostRedirect",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet\\ Settings\\\\IEHardenIENoWarn",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Internet\\ Explorer\\\\Main\\\\NoProtectedModeBanner",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Internet\\ Explorer\\\\Main\\\\IE9RunOncePerInstall",
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            for regkey in self.check_key(pattern=indicator, regex=True, actions=["regkey_written"], all=True):
                self.mark_ioc("registry", regkey)

        return self.has_marks()
