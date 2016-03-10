# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class PWDumpFile(Signature):
    name = "pwdump_file"
    description = "Creates known PWDump/FGDump files"
    severity = 3
    categories = ["hacktool"]
    families = ["pwdump"]
    authors = ["RedSocks"]
    minimum = "2.0"

    files_re = [
        ".*lsremora\\.dll",
        ".*pwdump\\.exe",
    ]

    def on_complete(self):
        for indicator in self.files_re:
            for filepath in self.check_file(pattern=indicator, regex=True, all=True):
                self.mark_ioc("file", filepath)

        return self.has_marks()
