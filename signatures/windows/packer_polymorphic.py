# Copyright (C) 2013 Lord Alfred Remorin
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import math

from lib.cuckoo.common.abstracts import Signature

try:
    import pydeep
    HAVE_SSDEEP = True
except ImportError:
    HAVE_SSDEEP = False

class Polymorphic(Signature):
    name = "packer_polymorphic"
    description = "Creates a slightly modified copy of itself"
    severity = 3
    categories = ["packer"]
    authors = ["lordr"]
    minimum = "2.0"

    def on_complete(self):
        if not HAVE_SSDEEP:
            return

        if self.get_results("target", {}).get("category") != "file":
            return

        f = self.get_results("target", {}).get("file", {})
        target_ssdeep = f.get("ssdeep")
        target_sha1 = f.get("sha1")
        target_size = f.get("size")

        if not target_ssdeep:
            return

        for drop in self.get_results("dropped", []):
            if drop["sha1"] == target_sha1:
                continue

            if math.fabs(target_size - drop["size"]) >= 1024:
                continue

            drop_ssdeep = drop["ssdeep"]
            if not drop_ssdeep:
                continue

            if pydeep.compare(target_ssdeep, drop_ssdeep) > 20:
                self.mark(file=drop, description="Possibly a polymorphic version of itself")

        return self.has_marks()
