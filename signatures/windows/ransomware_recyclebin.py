# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com), Updated 2016 for Cuckoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class RansomwareRecyclebin(Signature):
    name = "ransomware_recyclebin"
    description = "Empties the Recycle Bin, indicative of Ransomware"
    severity = 3
    categories = ["ransomware"]
    authors = ["Optiv"]
    minimum = "2.0"

    def on_complete(self):
        for deleted in self.check_file("C:\\\\RECYCLER\\\\.*", actions=["file_deleted"], regex=True, all=True):
            self.mark_ioc("file", deleted)

        return self.has_marks()
