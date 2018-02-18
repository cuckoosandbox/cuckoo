# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re

from lib.cuckoo.common.abstracts import Signature

class SelfDeleteBat(Signature):
    name = "self_delete_bat"
    description = "Creates and runs a batch file to remove the original binary"
    severity = 3
    categories = ["trojan"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    indicator = (
        "@echo.*off.*"
        ":.*"
        "del.*"
        "if.*exist.*goto.*"
        "del.*"
    )

    def on_complete(self):
        for dropped in self.get_results("dropped", []):
            if not dropped["name"].endswith(".bat"):
                continue

            contents = open(dropped["path"], "rb").read()
            if re.match(self.indicator, contents, re.I | re.S):
                self.mark_ioc("file", dropped["name"])

        return self.has_marks()
