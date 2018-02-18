# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class CreatesSuspiciousProcess(Signature):
    name = "suspicious_process"
    description = "Creates a suspicious process"
    severity = 2
    categories = ["packer"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    processes = [
        "svchost", "powershell", "regsvr32", "bcdedit", "mshta", "schtasks",
        "wmic", "cmd.exe",
    ]

    def on_complete(self):
        for cmdline in self.get_command_lines():
            for process in self.processes:
                if process in cmdline.lower():
                    self.mark_ioc("cmdline", cmdline)
                    break

        return self.has_marks()
