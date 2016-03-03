# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class MircFile(Signature):
    name = "mirc_file"
    description = "Checks presence of mIRC Chat Client"
    severity = 3
    categories = ["tool"]
    families = ["mirc"]
    authors = ["RedSocks"]
    minimum = "2.0"

    files_re = [
        "C:\\mIRC\\mirc.ini",
        "D:\\mIRC\\mirc.ini",
    ]

    def on_complete(self):
        for indicator in self.files_re:
            if self.check_file(pattern=indicator):
                self.mark_ioc("file", indicator)

        return self.has_marks()
