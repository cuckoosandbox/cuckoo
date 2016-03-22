# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class UroburosMutexes(Signature):
    name = "uroburos_mutexes"
    description = "Creates known Turla/Uroburos APT mutexes"
    severity = 3
    categories = ["rat"]
    families = ["uroburos"]
    authors = ["RedSocks"]
    minimum = "2.0"

    files_re = [
        ".*\\\\drivers\\\\wo2ifsl.sys",
        ".*\\\\drivers\\\\acpied.sys",
        ".*\\\\drivers\\\\atmarpd.sys",
        ".*\\\\temp\\\\msmsgsmon.exe",
        ".*\\\\temp\\\\msdattst.ocx",
    ]

    def on_complete(self):
        for indicator in self.files_re:
            if self.check_mutex(pattern=indicator, regex=True):
                return True

            if self.check_file(pattern=indicator, regex=True):
                return True
