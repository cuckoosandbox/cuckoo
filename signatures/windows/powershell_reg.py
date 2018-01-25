# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re
import shlex

from lib.cuckoo.common.abstracts import Signature

class PowershellRegAdd(Signature):
    name = "powershell_reg_add"
    description = "Powershell script adds registry entries"
    severity = 3
    categories = ["script", "powershell"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"

    def on_complete(self):
        lower = "".join(self.get_command_lines()).lower()
        if "powershell" in lower and "reg add" in lower:
            self.mark_ioc("cmd", lower)
            return True

        encre = re.compile("\-[e^]{1,2}[ncodema^]+")
        for cmdline in self.get_command_lines():
            lower = cmdline.lower()
            if encre.search(lower):
                # Powershell is b64 encoded
                script, args = None, shlex.split(cmdline)
                for idx, arg in enumerate(args):
                    if not encre.search(arg.lower()):
                        # Not the encoded argument
                        continue

                    try:
                        script = args[idx+1].decode("base64").decode("utf16")
                        if "reg add" in script.lower():
                            self.mark_ioc("cmd", script)
                            return True
                    except:
                        pass

        return False
