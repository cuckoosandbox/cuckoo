# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class ProcMemDumpURLs(Signature):
    name = "memdump_urls"
    description = "Potentially malicious URLs were found in the process memory dump"
    severity = 2
    categories = ["unpacking"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        for procmem in self.get_results("procmemory", []):
            for url in procmem.get("urls", []):
                self.mark_ioc("url", url)

        return self.has_marks()
