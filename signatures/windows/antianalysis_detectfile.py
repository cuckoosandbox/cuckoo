# Copyright (C) 2015 KillerInstinct, Updated 2016 for cuckoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AntiAnalysisDetectFile(Signature):
    name = "antianalysis_detectfile"
    description = "Attempts to identify installed analysis tools by a known file location"
    severity = 3
    categories = ["anti-analysis"]
    authors = ["KillerInstinct"]
    minimum = "2.0"

    file_indicators = [
        "[A-Za-z]:\\\\analysis",
        "[A-Za-z]:\\\\iDEFENSE",
        "[A-Za-z]:\\\\stuff\\\\odbg110",
        "[A-Za-z]:\\\\gnu\\\\bin",
        "[A-Za-z]:\\\\Virus\\ Analysis",
        "[A-Za-z]:\\\\popupkiller\\.exe",
        "[A-Za-z]:\\\\tools\\\\execute\\.exe",
        "[A-Za-z]:\\\\MDS\\\\WinDump\\.exe",
        "[A-Za-z]:\\\\guest_tools\\\\start\\.bat",
        "[A-Za-z]:\\\\tools\\\\aswsnx",
        "[A-Za-z]:\\\\tools\\\\decodezeus",
        "[A-Za-z]:\\\\tool\\\\malmon",
        "[A-Za-z]:\\\\sandcastle\\\\tools",
        "[A-Za-z]:\\\\tsl\\\\raptorclient\\.exe",
        "[A-Za-z]:\\\\kit\\\\procexp\\.exe",
        "[A-Za-z]:\\\\winap\\\\ckmon\\.pyw",
        "[A-Za-z]:\\\\vmremote\\\\vmremoteguest\\.exe",
        "[A-Za-z]:\\\\Program\\ Files(\\ \\(x86\\))?\\\\Fiddler",
        "[A-Za-z]:\\\\ComboFix",
    ]

    def on_complete(self):
        for indicator in self.file_indicators:
            for match in self.check_file(pattern=indicator, regex=True, all=True):
                self.mark_ioc("file", match)

        return self.has_marks()
