# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class CreatesDocument(Signature):
    name = "creates_doc"
    description = "Creates (office) documents on the filesystem"
    severity = 2
    categories = ["generic"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    pattern = ".*\\.(doc|docm|dotm|docx|ppt|pptm|pptx|potm|ppam|ppsm|xls|xlsm|xlsx|pdf)$"

    def on_complete(self):
        for filepath in self.check_file(pattern=self.pattern, actions=["file_written"], regex=True, all=True):
            self.mark_ioc("file", filepath)

        return self.has_marks()
