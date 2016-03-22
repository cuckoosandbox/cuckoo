# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re

from lib.cuckoo.common.abstracts import Signature

class RansomwareBcdedit(Signature):
    name = "ransomware_bcdedit"
    description = "Runs bcdedit commands specific to ransomware"
    severity = 3
    categories = ["ransomware"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    indicator = (
        "bcdedit.*/set.*(bootems|optionsedit|advancedoptions|bootstatuspolicy|recoveryenabled)"
    )

    def on_complete(self):
        for cmdline in self.get_command_lines():
            if re.match(self.indicator, cmdline):
                self.mark_ioc("cmdline", cmdline)

        return self.has_marks()
