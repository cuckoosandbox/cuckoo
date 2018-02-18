# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cuckoo.common.abstracts import Extractor
from cuckoo.processing.static import LnkShortcut

class LnkHeader(Extractor):
    yara_rules = "LnkHeader"
    minimum = "2.0.5"

    def handle_yara(self, filepath, match):
        lnk = LnkShortcut(filepath).run()
        self.enhance(filepath, "lnk", lnk)
        self.push_command_line("%s %s" % (lnk["basepath"], lnk["cmdline"]))
