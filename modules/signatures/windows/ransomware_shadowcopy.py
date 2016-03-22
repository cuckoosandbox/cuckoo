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

    indicator = (
        "wmic.*shadowcopy.*delete.*(/nointeractive)?"
    )

    def on_complete(self):
        for cmdline in self.get_command_lines():
            if re.match(self.indicator, cmdline, re.I):
                self.mark_ioc("cmdline", cmdline)

        return self.has_marks()
