# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class InceptionAPT(Signature):
    name = "apt_inception"
    description = "Creates known Inception APT files, registry keys and/or mutexes"
    severity = 3
    categories = ["apt"]
    families = ["inception"]
    authors = ["RedSocks"]
    references = [
        "https://www.bluecoat.com/security-blog/2014-12-09/blue-coat-exposes-%E2%80%9C-inception-framework%E2%80%9D-very-sophisticated-layered-malware",
    ]
    minimum = "2.0"

    files_re = [
        ".*polymorphed.*dll",
    ]

    def on_complete(self):
        for indicator in self.files_re:
            for filepath in self.check_file(pattern=indicator, regex=True, all=True):
                self.mark_ioc("file", filepath)

        return self.has_marks()
