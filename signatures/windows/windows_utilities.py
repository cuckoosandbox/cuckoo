# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class UsesWindowsUtilities(Signature):
    name = "uses_windows_utilities"
    description = "Uses Windows utilities for basic Windows functionality"
    severity = 2
    categories = ["commands", "lateral"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"
    references = ["http://blog.jpcert.or.jp/2016/01/windows-commands-abused-by-attackers.html"]

    utilities = [
        "at ",
        "at.exe",
        "attrib",
        "del",
        "dir",
        "erase",
        "fsutil",
        "getmac",
        "ipconfig",
        "net ",
        "net.exe",
        "netsh",
        "netstat",
        "ping",
        "qwinsta",
        "reg ",
        "reg.exe",
        "regsrv32",
        "route",
        "runas",
        "rwinsta",
        "sc ",
        "sc.exe",
        "schtasks",
        "shutdown",
        "systeminfo",
        "tasklist",
        "taskkill",
        "telnet",
        "whoami",
        "wusa"
    ]

    def on_complete(self):
        for cmdline in self.get_command_lines():
            for utility in self.utilities:
                if cmdline.lower().startswith(utility):
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()

class SuspiciousCommandTools(Signature):
    name = "suspicious_command_tools"
    description = "Uses suspicious command line tools or Windows utilities"
    severity = 3
    categories = ["commands", "lateral"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    utilities = [
        "accesschk",
        "accessenum",
        "adexplorer",
        "adinsight",
        "adrestore",
        "autologon",
        "autoruns",
        "bitsadmin",
        "bginfo",
        "cacls",
        "csvde",
        "dsquery",
        "icacls",
        "psexec",        
        "psfile",
        "psgetsid",
        "psinfo",
        "psping",
        "pskill",
        "pslist",
        "psloggedon",
        "psloglist",
        "pspasswd",
        "psservice",
        "psshutdown",
        "pssuspend",
        "rexec",
        "shareenum",
        "shellrunas",
        "volumeid",
        "wevtutil",
        "whois"
        "xcacls"
    ]

    def on_complete(self):
        for cmdline in self.get_command_lines():
            for utility in self.utilities:
                if cmdline.lower().startswith(utility):
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()
