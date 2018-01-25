# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com), Updated 2016 for cuckoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class InstalledApps(Signature):
    name = "recon_programs"
    description = "Collects information about installed applications"
    severity = 3
    categories = ["recon"]
    authors = ["Optiv"]
    minimum = "2.0"

    filter_apinames = "RegQueryValueExA", "RegQueryValueExW"

    def on_call(self, call, process):
        keyname = call["arguments"]["regkey"]
        uninstall = "\\microsoft\\windows\\currentversion\\uninstall"
        if (keyname and uninstall in keyname.lower() and keyname.lower().endswith("displayname")):
            app = call["arguments"]["value"]
            if app:
                self.mark_call()

    def on_complete(self):
        return self.has_marks()
