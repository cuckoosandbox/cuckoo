# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class VMWareInInstruction(Signature):
    name = "antivm_vmware_in_instruction"
    description = "Detects VMWare through the in instruction feature"
    severity = 3
    categories = ["anti-vm"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "__exception__",

    def on_call(self, call, process):
        insn = call["arguments"]["exception"].get("instruction", "")
        if not insn.startswith("in "):
            return

        for value in call["arguments"]["registers"].values():
            if value == 0x564d5868:
                self.mark_call()
                return True
