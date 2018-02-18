# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re

from lib.cuckoo.common.abstracts import Signature

class ExecBitsAdmin(Signature):
    name = "exec_bits_admin"
    description = "BITSAdmin Tool has been invoked to download a file"
    severity = 3
    categories = ["script", "dropper"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        lower = "".join(self.get_command_lines()).lower()
        if "bitsadmin" in lower and "/download" in lower:
            url = re.search(
                "bitsadmin .+ \/download .* (http:\/\/[^\s]+)", lower
            )
            if url:
                self.mark_ioc("url", url.group(1))
            return True
