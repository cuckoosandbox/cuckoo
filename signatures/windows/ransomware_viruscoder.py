# Copyright (C) 2016 Justaguy @ Cybersprint B.V.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re

from lib.cuckoo.common.abstracts import Signature

class ransomware_viruscoder(Signature):
    name = "ransomware_viruscoder"
    description = "Uses an extension used by Viruscoder"
    severity = 3
    categories = ["Ransomware"]
    authors = ["Cybersprint"]
    minimum = "2.0"
    families = ["Ransomware","Viruscoder"]
    postdata_re = "[a-z0-9\\.-]"
    pattern = (
        ".*\\.(xtbl)$"
    )
    
    def on_complete(self):
        for filepath in self.check_file(pattern=self.pattern, actions=["file_written"], regex=True, all=True):
                self.mark_ioc("LockedFile", filepath)
        return self.has_marks()

