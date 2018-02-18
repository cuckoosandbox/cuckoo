# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com), Updated 2016 for Cuckoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class RemovesZoneIdADS(Signature):
    name = "removes_zoneid_ads"
    description = "Attempts to remove evidence of file being downloaded from the Internet"
    severity = 3
    categories = ["generic"]
    authors = ["Optiv"]
    minimum = "2.0"

    def on_complete(self):
        for deletedfile in self.get_files(actions=["file_deleted"]):
            if deletedfile.endswith(":Zone.Identifier"):
                self.mark_ioc("file", deletedfile)

        return self.has_marks()
