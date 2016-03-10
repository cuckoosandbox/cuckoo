# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class VirtualPCIllegalInstruction(Signature):
    name = "antivm_virtualpc_illegal_instruction"
    description = "Detects VirtualPC through a magic instruction"
    severity = 3
    categories = ["anti-vm"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "__exception__",

    def on_call(self, call, process):
        insn_r = call["arguments"]["exception"].get("instruction_r", "")
        if insn_r.startswith("0f 3f 0d 00"):
            self.mark_call()
            return True
