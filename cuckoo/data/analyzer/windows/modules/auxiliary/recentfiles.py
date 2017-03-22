# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import random

from lib.common.abstracts import Auxiliary
from lib.common.defines import SHELL32, SHARD_PATHA
from lib.common.exceptions import CuckooError
from lib.common.rand import random_string
from lib.common.registry import set_regkey_full

log = logging.getLogger(__name__)

class RecentFiles(Auxiliary):
    """Populates the Desktop with recent files in order to combat recent
    anti-sandbox measures."""

    extensions = [
        "txt", "rtf", "doc", "docx", "docm", "ppt", "pptx",
    ]

    def start(self):
        if "USERPROFILE" not in os.environ:
            raise CuckooError(
                "Unable to populate recent files as the USERPROFILE "
                "environment variable is missing."
            )

        desktop = os.path.join(os.environ["USERPROFILE"], "Desktop")

        for idx in xrange(random.randint(5, 10)):
            filename = random_string(10, random.randint(10, 20))
            ext = random.choice(self.extensions)
            filepath = os.path.join(desktop, "%s.%s" % (filename, ext))
            open(filepath, "wb").write(os.urandom(random.randint(30, 999999)))

            SHELL32.SHAddToRecentDocs(SHARD_PATHA, filepath)

            set_regkey_full(
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\12.0\\"
                "Word\\File MRU\\Item %d" % (idx + 1),
                "REG_SZ", "[F00000000][T01D1C40000000000]*%s" % filepath,
            )
