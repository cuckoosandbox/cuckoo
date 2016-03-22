# Copyright (C) 2012 Michael Boman (@mboman)
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

import re

from lib.cuckoo.common.abstracts import Signature

class Autorun(Signature):
    name = "persistence_autorun"
    description = "Installs itself for autorun at Windows startup"
    severity = 3
    categories = ["persistence"]
    authors = ["Michael Boman", "nex", "securitykitten", "Cuckoo Technologies"]
    minimum = "2.0"

    regkeys_re = [
        ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
        ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce",
        ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServices",
        ".*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnceEx",
        ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServicesOnce",
        ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon$",
        ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Notify$",
        ".*\\\\Software\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Userinit$",
        ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\Run$",
        ".*\\\\SOFTWARE\\\\Microsoft\\\\Active\\ Setup\\\\Installed Components\\\\.*",
        ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Windows\\\\Appinit_Dlls.*",
        ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\SharedTaskScheduler.*",
        ".*\\\\Software\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\[^\\\\]+\\\\(?!DisableExceptionChainValidation$).*",
        ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Shell$",
        ".*\\\\System\\\\CurrentControlSet\\\\Services.*",
        ".*\\\\SOFTWARE\\\\Classes\\\\Exefile\\\\Shell\\\\Open\\\\Command\\\\\\(Default\\).*",
        ".*\\\\Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\load$",
        ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\ShellServiceObjectDelayLoad$",
    ]

    files_re = [
        ".*\\\\win\.ini$",
        ".*\\\\system\\.ini$",
        ".*\\\\Start\\ Menu\\\\Programs\\\\Startup",
    ]

    command_lines_re = [
        ".*schtasks.*/create.*/sc",
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            for regkey in self.check_key(pattern=indicator, regex=True, actions=["regkey_written"], all=True):
                self.mark_ioc("registry", regkey)

        for indicator in self.files_re:
            for filepath in self.check_file(pattern=indicator, regex=True, actions=["file_written"], all=True):
                self.mark_ioc("file", filepath)

        for indicator in self.command_lines_re:
            for cmdline in self.get_command_lines():
                if re.match(indicator, cmdline, re.I):
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()
