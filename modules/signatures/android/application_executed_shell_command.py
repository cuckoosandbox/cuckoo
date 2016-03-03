# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AndroidShellCommands(Signature):
    name = "application_executed_shell_command"
    description = "Application Executed Shell Command (Dynamic)"
    severity = 4
    categories = ["android"]
    authors = ["Check Point Software Technologies LTD"]
    minimum = "2.0"

    def on_complete(self):
        if self.get_droidmon("commands", []):
            return True
