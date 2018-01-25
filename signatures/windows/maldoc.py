# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class MaliciousDocumentURLs(Signature):
    name = "malicious_document_urls"
    description = "Potentially malicious URL found in document"
    severity = 3
    categories = ["downloader"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = [
        "InternetCrackUrlW",
    ]

    filter_analysistypes = "file",

    def on_call(self, call, process):
        if process["process_name"].lower() == "wscript.exe":
            self.mark_ioc("url", call["arguments"]["url"])

    def on_complete(self):
        return self.has_marks()
