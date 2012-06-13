# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging

try:
    import yara
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.abstracts import Processing

log = logging.getLogger(__name__)

class YaraSignatures(Processing):
    """Yara signature processing."""

    def run(self):
        """Run Yara processing.
        @return: hash with matches.
        """
        self.key = "yara"
        matches = []

        if HAVE_YARA:
            try:
                rules = yara.compile(filepath=os.path.join(CUCKOO_ROOT, "data", "yara", "index.yar"))
                for match in rules.match(self.file_path):
                    matches.append({"name" : match.rule, "meta" : match.meta})
            except yara.Error as e:
                log.warning("Unable to match Yara signatures: %s" % e[1])
        else:
            log.warning("Yara is not installed, skip")

        return matches
