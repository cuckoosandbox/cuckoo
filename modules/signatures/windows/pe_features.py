# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re

from lib.cuckoo.common.abstracts import Signature

class PEFeatures(Signature):
    name = "pe_features"
    description = "The executable has PE anomalies (could be a false positive)"
    severity = 1
    categories = ["packer"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    section_names = [
        ".text", ".rdata", ".data", ".pdata", ".DATA", ".reloc", ".idata",
        ".rsrc", ".shared", ".bss", ".edata", ".tls", ".CRT", ".eh_fram",
        ".xdata", "UPX0", "UPX1", "UPX2",
    ]

    section_names_re = [
        "/[\\d]+$",
    ]

    def on_complete(self):
        for section in self.get_results("static", {}).get("pe_sections", []):
            if section["name"] in self.section_names:
                continue

            for section_name_re in self.section_names_re:
                if re.match(section_name_re, section["name"]):
                    break
            else:
                self.mark_ioc("section", section["name"])

        return self.has_marks()
