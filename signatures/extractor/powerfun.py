# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re
import zlib

from cuckoo.common.abstracts import Extractor

class Powerfun(Extractor):
    yara_rules = "Powerfun"

    def handle_yara(self, filepath, match):
        sc = match.string("Shellcode", 0)
        base64regex = re.compile("FromBase64String\(['\"]([^)]+)['\"]\)")
        arg = base64regex.search(sc)
        if arg:
            # Powerfun invokes a second-stage PS script
            # This script is b64encoded and gziped
            script = zlib.decompress(
                arg.group(1).replace("'", "").decode("base64"),
                16 + zlib.MAX_WBITS
            )
            # The shellcode in the script is also b64 encoded
            arg = base64regex.search(script)
            if arg:
                self.push_shellcode(
                    arg.group(1).replace("'", "").decode("base64")
                )
