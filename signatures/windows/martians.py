# Copyright (C) 2016 Cuckoo Foundation, Will Metcalf (william.metcalf@gmail.com), Kevin Ross
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class ProcessMartian(Signature):
    name = "process_martian"
    description = "One or more martian processes was created"
    severity = 3
    categories = ["martian", "exploit", "dropper"]
    authors = ["Cuckoo Technologies", "Will Metcalf", "Kevin Ross"]
    minimum = "2.0"

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.whitelist_procs = [
            "acrord32.exe",
            "acrord64.exe",
            "chrome.exe",
            "cscript.exe",
            "excel.exe",
            "firefox.exe",
            "iexplore.exe",
            "outlook.exe",
            "powerpnt.exe",
            "powershell.exe",
            "winword.exe",
            "wordview.exe",
            "wscript.exe"
            "wspub.exe"
        ]

        self.whitelist_re = [
            "\\\"C:\\\\\Program\\ Files(\\ \\(x86\\))?\\\\Internet\\ Explorer\\\\iexplore\\.exe\\\"\\ SCODEF:\\d+ CREDAT:\\d+",
            "^[A-Z]\:\\Program Files(?:\s\(x86\))?\\Microsoft Office\\(?:Office1[1-5]\\)?(?:WINWORD|OUTLOOK|POWERPNT|EXCEL|WORDVIEW)\.EXE",
            "C\\:\\\\Windows\\\\System32\\\\wscript\\.exe",
            "C\\:\\\\Program Files(?:\s\\(x86\\))?\\\\Adobe\\\\Reader\\ \\d+\\.\\d+\\\\Reader\\\\AcroRd64\\.exe",
            "C\\:\\\\Program Files(?:\s\\(x86\\))?\\\\Adobe\\\\Reader\\ \\d+\\.\\d+\\\\Reader\\\\AcroRd64\\.exe",
            "C\\:\\\\Program Files(?:\s\\(x86\\))?\\\\Java\\\\jre\\d+\\\\bin\\\\j(?:avaw?|p2launcher)\\.exe",
            "C\\:\\\\Program Files(?:\s\\(x86\\))?\\\\Microsoft SilverLight\\\\(?:\\d+\\.)+\\d\\\\agcp\\.exe",
            "C\\:\\\\Windows\\\\System32\\\\ntvdm\\.exe",
            "C\\:\\\\Windows\\\\System32\\\\svchost\\.exe",
            "C\\:\\\\Program Files(?:\s\\(x86\\))?\\\\internet explorer\\\\iexplore\.exe",
            # remove this one at some point
            "C\\:\\\\Windows\\\\System32\\\\rundll32\\.exe",
            "C\\:\\\\Windows\\\\System32\\\\drwtsn32\\.exe",
            "C\\:\\\\Windows\\\\splwow64\\.exe",
            "C\\:\\\\Program Files(?:\s\\(x86\\))?\\\\Common Files\\\\Microsoft Shared\\\\office1[1-6]\\\\off(?:lb|diag)\\.exe",
            "C\\:\\\\Program Files(?:\s\\(x86\\))?\\\\Common Files\\\\Microsoft Shared\\\\dw\\\\dw(?:20)?\\.exe",
            "C\\:\\\\Windows\\\\system32\\\\dwwin\\.exe",
            "C\\:\\\\Windows\\\\system32\\\\WerFault\\.exe",
            "C\\:\\\\Windows\\\\syswow64\\\\WerFault\\.exe"
        ]

    def on_complete(self):
        for process in self.get_results("behavior", {}).get("generic", []):
            if process["process_name"].lower() not in self.whitelist_procs:
                continue

            for cmdline in process.get("summary", {}).get("command_line", []):
                for regex in self.whitelist_re:
                    if re.match(regex, cmdline, re.I):
                        break
                else:
                    pname = process["process_name"].lower()
                    if cmdline != "":
                        self.mark(
                            parent_process=pname,
                            martian_process=cmdline,
                        )

        return self.has_marks()
