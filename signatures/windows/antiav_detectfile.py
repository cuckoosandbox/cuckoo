# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com), Updated 2016 for cuckoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class AntiAVDetectFile(Signature):
    name = "antiav_detectfile"
    description = "Attempts to identify installed AV products by installation directory"
    severity = 3
    categories = ["anti-av"]
    authors = ["Optiv"]
    minimum = "2.0"

    file_indicators = [
        ".*\\\\AVAST\\ Software",
        ".*\\\\Avira\\ GmbH",
        ".*\\\\Avira",
        ".*\\\\Kaspersky\\ Lab",
        ".*\\\\Kaspersky\\ Lab\\ Setup\\ Files",
        ".*\\\\DrWeb",
        ".*\\\\Norton\\ AntiVirus",
        ".*\\\\Norton\\ (Security with Backup|Internet Security)\\\\"
        ".*\\\\ESET",
        ".*\\\\Agnitum",
        ".*\\\\Panda\\ Security",
        ".*\\\\McAfee",
        ".*\\\\McAfee\.com",
        ".*\\\\Trend\\ Micro",
        ".*\\\\BitDefender",
        ".*\\\\ArcaBit",
        ".*\\\\Online\\ Solutions",
        ".*\\\\AnVir\\ Task\\ Manager",
        ".*\\\\Alwil\\ Software",
        ".*\\\\Symantec$",
        ".*\\\\AVG",
        ".*\\\\Xore",
        ".*\\\\Symantec\\ Shared",
        ".*\\\\a-squared\\ Anti-Malware",
        ".*\\\\a-squared\\ HiJackFree",
        ".*\\\\avg8",
        ".*\\\\Doctor\\ Web",
        ".*\\\\f-secure",
        ".*\\\\F-Secure\\ Internet\\ Security",
        ".*\\\\G\\ DATA",
        ".*\\\\P\\ Tools",
        ".*\\\\P\\ Tools\\ Internet\\ Security",
        ".*\\\\K7\\ Computing",
        ".*\\\\Vba32",
        ".*\\\\Sunbelt\\ Software",
        ".*\\\\FRISK\\ Software",
        ".*\\\\Security\\ Task\\ Manager",
        ".*\\\\Zillya\\ Antivirus",
        ".*\\\\Spyware\\ Terminator",
        ".*\\\\Lavasoft",
        ".*\\\\BlockPost",
        ".*\\\\DefenseWall\\ HIPS",
        ".*\\\\DefenseWall",
        ".*\\\\Microsoft\\ Antimalware",
        ".*\\\\Microsoft\\ Security\\ Essentials",
        ".*\\\\Sandboxie",
        ".*\\\\Positive\\ Technologies",
        ".*\\\\UAenter",
        ".*\\\\Malwarebytes",
        ".*\\\\Malwarebytes'\\ Anti-Malware",
        ".*\\\\Microsoft\\ Security\\ Client",
        ".*\\\\System32\\\\drivers\\\\kl1\\.sys",
        ".*\\\\System32\\\\drivers\\\\(tm((actmon|comm)\\.|e(vtmgr\\.|ext\\.)|(nciesc|tdi)\\.)|TMEBC32\\.)sys",
    ]

    def on_complete(self):
        for indicator in self.file_indicators:
            for match in self.check_file(pattern=indicator, regex=True, all=True):
                self.mark_ioc("file", match)

        return self.has_marks()
