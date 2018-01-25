# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class OfficeDDE(Signature):
    name = "office_dde"
    description = "Malicious document featuring Office DDE has been identified"
    severity = 3
    categories = ["dropper"]
    minimum = "2.0.5"

    def on_extract(self, match):
        if match.category != "office":
            return

        if not match.yara or not match.yara[0].name.startswith("OfficeDDE"):
            return

        self.mark_config({
            "family": "Office DDE",
        })
        return True
