# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re

from lib.cuckoo.common.abstracts import Signature

class IEMartian(Signature):
    name = "ie_martian"
    description = "Internet Explorer creates one or more martian processes"
    severity = 3
    categories = ["martian"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    whitelist_re = [
        "\\\"C:\\\\\Program\\ Files(\\ \\(x86\\))?\\\\Internet\\ Explorer\\\\iexplore\\.exe\\\"\\ SCODEF:\\d+ CREDAT:\\d+$",
    ]

    def on_complete(self):
        for process in self.get_results("behavior", {}).get("generic", []):
            if process["process_name"] != "iexplore.exe":
                continue

            for cmdline in process.get("summary", {}).get("command_line", []):
                for regex in self.whitelist_re:
                    if re.match(regex, cmdline, re.I):
                        break
                else:
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()
