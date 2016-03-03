# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class ShutdownSystem(Signature):
    name = "shutdown_system"
    description = "Shuts down the system, generally used for bypassing sandboxing"
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "NtShutdownSystem",

    def on_call(self, call, process):
        self.mark_call()
        return True
