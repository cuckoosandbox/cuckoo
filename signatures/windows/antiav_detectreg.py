# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com), Updated 2016 for Cuckoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AntiAVDetectReg(Signature):
    name = "antiav_detectreg"
    description = "Attempts to identify installed AV products by registry key"
    severity = 3
    categories = ["anti-av"]
    authors = ["Optiv"]
    minimum = "2.0"

    reg_indicators = [
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Avg",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?AVAST\\ Software\\\\.*",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Avira",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Bitdefender",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?BitDefender\\\\.*",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Coranti",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Data\\ Fellows\\\\F-Secure",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Doctor\\ Web",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?ESET",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?ESET\\\\.*",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?G\\ Data",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Symantec",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?KasperskyLab\\\\.*",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?McAfee\\\\.*",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?McAfee\.com\\\\.*",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Microsoft\\ Antimalware",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Network\\ Associates\\\\TVD",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Panda\\ Software",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?rising",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Softed\\\\ViGUARD",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Sophos",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Sophos\\\\.*",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?TrendMicro",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?VBA32",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Zone\\ Labs\\\\ZoneAlarm",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\App\\ Paths\\\\mbam.exe",
        ".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\services\\\\Avg.*",
        ".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\services\\\\AVP.*",
        ".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\services\\\\avast!\\ Antivirus.*",
        ".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\services\\\\RsMgrSvc.*",
        ".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\services\\\\fshoster.*",
        ".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\services\\\\cmdvirth.*",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\AVG_UI",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\AVP",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\mcui_exe",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\mcpltui_exe",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Bdagent",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Trend\\ Micro\\ Titanium",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Trend\\ Micro\\ Client\\ Framework",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\avast",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\MSC",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\BullGuard",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Sophos\\ AutoUpdate\\ Monitor",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\SpIDerAgent",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\APVXDWIN",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\WRSVC",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\emsisoft\\ anti-malware",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\ISTray",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\G\\ Data\\ AntiVirus\\ Tray.*",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\ZoneAlarm",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Bkav",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\V3\\ Application",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Baidu\\ Antivirus",
    ]

    def on_complete(self):
        for indicator in self.reg_indicators:
            for regkey in self.check_key(pattern=indicator, regex=True, all=True):
                self.mark_ioc("registry", regkey)

        return self.has_marks()
