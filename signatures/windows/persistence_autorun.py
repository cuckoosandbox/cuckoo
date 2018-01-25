# Copyright (C) 2012,2014,2015 Michael Boman (@mboman), Optiv, Inc. (brad.spengler@optiv.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Based on information from http://antivirus.about.com/od/windowsbasics/tp/autostartkeys.htm

# Additional keys added from SysInternals Administrators Guide

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class Autorun(Signature):
    name = "persistence_autorun"
    description = "Installs itself for autorun at Windows startup"
    severity = 3
    categories = ["persistence"]
    authors = ["Michael Boman", "nex", "securitykitten", "Cuckoo Technologies", "Optiv", "KillerInstinct", "Kevin Ross"]
    minimum = "2.0"

    regkeys_re = [
        ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\.*",
        ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce\\\\.*",
        ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServices\\\\.*",
        ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnceEx\\\\.*",
        ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServicesOnce\\\\.*",
        ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Notify\\\\.*",
        ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Userinit$",
        ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\Run\\\\.*",
        ".*\\\\Microsoft\\\\Active\\ Setup\\\\Installed Components\\\\.*",
        ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Windows\\\\AppInit_DLLs$",
        ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\SharedTaskScheduler\\\\.*",
        ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\[^\\\\]*\\\\\Debugger$",
        ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Shell$",
        ".*\\\\System\\\\(CurrentControlSet|ControlSet001)\\\\Services\\\\[^\\\\]*\\\\ImagePath$",
        ".*\\\\System\\\\(CurrentControlSet|ControlSet001)\\\\Services\\\\[^\\\\]*\\\\Parameters\\\\ServiceDLL$",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\Exefile\\\\Shell\\\\Open\\\\Command\\\\\(Default\)$",
        ".*\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\load$",
        ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\ShellServiceObjectDelayLoad\\\\.*",
        ".*\\\\System\\\\(CurrentControlSet|ControlSet001)\\\\Control\\\\Session\\ Manager\\\\AppCertDlls\\\\.*",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\clsid\\\\[^\\\\]*\\\\InprocServer32\\\\.*",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\clsid\\\\[^\\\\]*\\\\LocalServer32\\\\.*",
    ]

    files_re = [
        ".*\\\\win\.ini$",
        ".*\\\\system\.ini$",
        ".*\\\\Start Menu\\\\Programs\\\\Startup\\\\.*",
        ".*\\\\WINDOWS\\\\Tasks\\\\.*"
    ]

    command_lines_re = [
        ".*schtasks.*/create.*/sc",
    ]

    whitelists = [
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\clsid\\\\{CAFEEFAC-0017-0000-FFFF-ABCDEFFEDCBA}\\\\InprocServer32\\\\.*",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\clsid\\\\[^\\\\]*\\\\InprocServer32\\\\ThreadingModel$"
    ]

    filter_apinames = [
        "RegSetValueExA",
        "RegSetValueExW",
        "NtSetValueKey",
        "CreateServiceA",
        "CreateServiceW",
    ]

    def on_call(self, call, process):
        if call["api"] == "CreateServiceA" or call["api"] == "CreateServiceW":
            starttype = call["arguments"]["start_type"]
            servicename = call["arguments"]["service_name"]
            servicepath = call["arguments"]["filepath"]
            if starttype < 3:
                self.mark(
                    service_name=servicename,
                    service_path=servicepath,
                )

        elif call["status"]:
            regkey = call["arguments"]["regkey"]
            regvalue = call["arguments"]["value"]
            in_whitelist = False
            for whitelist in self.whitelists:
                if re.match(whitelist, regkey, re.IGNORECASE):
                    in_whitelist = True
                    break
            if not in_whitelist:
                for indicator in self.regkeys_re:
                    if re.match(indicator, regkey, re.IGNORECASE) and regvalue != "c:\\program files\\java\\jre7\\bin\jp2iexp.dll":
                        self.mark(
                            reg_key=regkey,
                            reg_value=regvalue,
                        )

    def on_complete(self):
        for indicator in self.files_re:
            for filepath in self.check_file(pattern=indicator, regex=True, actions=["file_written"], all=True):
                self.mark_ioc("file", filepath)

        for indicator in self.command_lines_re:
            for cmdline in self.get_command_lines():
                if re.match(indicator, cmdline, re.I):
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()
