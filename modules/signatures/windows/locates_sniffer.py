# Copyright (C) 2010-2015 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class LocatesSniffer(Signature):
    name = "locates_sniffer"
    description = "Tries to locate whether any sniffers are installed"
    severity = 1
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    regkeys_re = [
        ".*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\App\\ Paths\\\\Wireshark.exe",
        ".*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\Wireshark",

        ".*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\App\\ Paths\\\\Fiddler.exe",
        ".*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\Fiddler",

        ".*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\Fiddler2",
        ".*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\App\\ Paths\\\\Fiddler2.exe",

        ".*\\\\Software\\\\Classes\\\\SOFTWARE\\\\IEInspectorSoft\\\\HTTPAnalyzerAddon",
        ".*\\\\Software\\\\Classes\\\\IEHTTPAnalyzer\\.HTTPAnalyzerAddOn",
        ".*\\\\Software\\\\Classes\\\\HTTPAnalyzerStd\\.HTTPAnalyzerStandAlone",

        ".*\\\\Software\\\\Classes\\\\Charles\\.AMF\\.Document",
        ".*\\\\Software\\\\Classes\\\\Charles\\.Document",
        ".*\\\\Software\\\\XK72\\ Ltd\\ folder",
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            regkey = self.check_key(pattern=indicator, regex=True)
            if regkey:
                self.mark_ioc("registry", regkey)

        return self.has_marks()
