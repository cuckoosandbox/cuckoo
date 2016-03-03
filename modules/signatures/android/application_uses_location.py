# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class ApplicationUsesLocation(Signature):
    name = "application_uses_location"
    description = "Application Uses Location (Dynamic)"
    severity = 5
    categories = ["android"]
    authors = ["Check Point Software Technologies LTD"]
    minimum = "2.0"

    def on_complete(self):
        if "location" in self.get_droidmon("data_leak"):
            return True
