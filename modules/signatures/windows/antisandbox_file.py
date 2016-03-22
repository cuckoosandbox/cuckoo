# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AntiSandboxFile(Signature):
    name = "antisandbox_file"
    description = "Looks for known filepaths where sandboxes execute samples"
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    files_re = [
        "[a-zA-Z]:\\\\sample\\.exe",
        "[a-zA-Z]:\\\\malware\\.exe",
    ]

    def on_complete(self):
        for indicator in self.files_re:
            for match in self.check_file(pattern=indicator, regex=True, all=True):
                self.mark_ioc("file", match)

        return self.has_marks()
