# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re

from lib.cuckoo.common.abstracts import Signature

class RansomwareShadowcopy(Signature):
    name = "ransomware_shadowcopy"
    description = "Removes the Shadow Copy to avoid recovery of the system"
    severity = 3
    categories = ["ransomware"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    cmdline_re = (
        "wmic.*shadowcopy.*delete.*(/nointeractive)?",
        "vssadmin.*delete.*shadows",
    )

    def on_complete(self):
        for cmdline in self.get_command_lines():
            for regex in self.cmdline_re:
                if re.match(regex, cmdline, re.I):
                    self.mark_ioc("cmdline", cmdline)
                    break

        return self.has_marks()
