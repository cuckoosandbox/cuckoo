# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com), Updated 2016 for Cuckoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DisablesSPDY(Signature):
    name = "disables_spdy"
    description = "Attempts to disable SPDY support in Firefox to improve web infostealing capability"
    severity = 3
    categories = ["generic"]
    authors = ["Optiv"]
    minimum = "2.0"

    filter_apinames = set(["NtWriteFile"])

    def on_call(self, call, process):
        buf = call["arguments"]["buffer"]
        if "network.http.spdy.enabled" in buf and "false" in buf:
            self.mark_call()

    def on_complete(self):
        return self.has_marks()
