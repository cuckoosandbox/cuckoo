# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class VMFirmware(Signature):
    name = "antivm_firmware"
    description = "Detects Virtual Machines through their custom firmware"
    severity = 3
    categories = ["anti-vm"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "NtQuerySystemInformation",

    def on_call(self, call, process):
        if call["flags"]["information_class"] == "SystemFirmwareTableInformation":
            self.mark_call()
            return True
