# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class SunBeltSandboxDetect(Signature):
    name = "antisandbox_sunbelt"
    description = "Tries to detect SunBelt Sandbox"
    severity = 3
    categories = ["anti-vm"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    dlls_re = [
        ".*api_log(\\.dll)?$",
        ".*dir_watch(\\.dll)?$",
    ]

    def on_complete(self):
        for dll_re in self.dlls_re:
            for filepath in self.check_file(pattern=dll_re, regex=True, all=True):
                self.mark_ioc("file", filepath)

            for dll in self.check_dll_loaded(pattern=dll_re, regex=True, all=True):
                self.mark_ioc("dll", dll)

        return self.has_marks()
