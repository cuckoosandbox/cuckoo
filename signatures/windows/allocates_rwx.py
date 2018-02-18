# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AllocatesRWX(Signature):
    name = "allocates_rwx"
    description = "Allocates read-write-execute memory (usually to unpack itself)"
    severity = 2
    categories = ["unpacking"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "NtAllocateVirtualMemory", "NtProtectVirtualMemory"

    def on_call(self, call, process):
        if call["flags"]["protection"] == "PAGE_EXECUTE_READWRITE":
            self.mark_call()
            return True
