# Copyright (C) 2010-2015 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class LocatesSniffer(Signature):
    name = "locates_sniffer"
    description = "Tries to locate whether any sniffers are installed"
    severity = 2
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    regkeys_re = [
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\App\\ Paths\\\\Wireshark.exe",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\Wireshark",

        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\App\\ Paths\\\\Fiddler.exe",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\Fiddler",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Fiddler2$",

        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\Fiddler2",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\App\\ Paths\\\\Fiddler2.exe",

        ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\SOFTWARE\\\\IEInspectorSoft\\\\HTTPAnalyzerAddon",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\IEHTTPAnalyzer\\.HTTPAnalyzerAddOn",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\HTTPAnalyzerStd\\.HTTPAnalyzerStandAlone",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\IEHTTPAnalyzerStd\\.HTTPAnalyzerStandAlone$",

        ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\SOFTWARE\\\\IEInspectorSoft.*",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\Charles\\.AMF\\.Document",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\Charles\\.Document",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?XK72\\ Ltd\\ folder",
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            for regkey in self.check_key(pattern=indicator, regex=True, all=True):
                self.mark_ioc("registry", regkey)

        return self.has_marks()
