# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cuckoo.common.abstracts import Extractor

class Unicorn(Extractor):
    yara_rules = "UnicornGen"

    def handle_yara(self, filepath, match):
        sc = match.string("Shellcode", 0)
        self.push_shellcode(
            "".join(chr(int(x, 16)) for x in sc[2:-1].split(","))
        )
