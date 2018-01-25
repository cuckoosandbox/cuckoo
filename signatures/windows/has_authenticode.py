# Copyright (C) 2010-2015 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class HasAuthenticode(Signature):
    name = "has_authenticode"
    description = "This executable is signed"
    severity = 1

    def on_complete(self):
        if self.get_results("static", {}).get("signature"):
            return True
