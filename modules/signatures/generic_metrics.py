# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class SystemMetrics(Signature):
    name = "uses_system_metrics"
    description = "Uses GetSystemMetrics"
    severity = 2
    categories = ["generic"]
    authors = ["Cuckoo Developers"]
    minimum = "0.7"
    evented = True

    # This is a signature template. It should be used as a skeleton for
    # creating custom signatures, therefore is disabled by default.
    # The event_apicall function is used in "evented" signatures.
    # These use a more efficient way of processing logged API calls.
    enabled = False

    def run(self):
        return False

    def event_apicall(self, call):
        if call["api"] == "GetSystemMetrics":
            return True

        return None