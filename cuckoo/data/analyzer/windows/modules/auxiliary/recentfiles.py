# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ctypes
import logging
import os
import random
import uuid

from lib.common.abstracts import Auxiliary
from lib.common.defines import SHELL32, SHARD_PATHA, PWSTR
from lib.common.exceptions import CuckooError
from lib.common.rand import random_string
from lib.common.registry import set_regkey_full

log = logging.getLogger(__name__)

class RecentFiles(Auxiliary):
    """Populate the Desktop with recent files in order to combat recent
    anti-sandbox measures."""

    extensions = [
        "txt", "rtf", "doc", "docx", "docm", "ppt", "pptx",
    ]

    locations = {
        "desktop": "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}",
        "documents": "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}",
        "downloads": "{374DE290-123F-4565-9164-39C4925E467B}",
    }

    def get_path(self):
        location = self.options.get("recentfiles", "documents")
        if location not in self.locations:
            log.warning(
                "Unknown RecentFiles location specified, "
                "defaulting to 'documents'."
            )
            location = "documents"

        dirpath = PWSTR()
        r = SHELL32.SHGetKnownFolderPath(
            uuid.UUID(self.locations[location]).get_bytes_le(),
            0, None, ctypes.byref(dirpath)
        )
        if r:
            log.warning("Error obtaining user directory: 0x%08x", r)
            return

        # TODO We should free the memory with CoTaskMemFree().
        return dirpath.value

    def start(self):
        dirpath = self.get_path()
        if not dirpath:
            return

        for idx in xrange(random.randint(5, 10)):
            filename = random_string(10, random.randint(10, 20))
            ext = random.choice(self.extensions)
            filepath = os.path.join(dirpath, "%s.%s" % (filename, ext))
            open(filepath, "wb").write(os.urandom(random.randint(30, 999999)))

            SHELL32.SHAddToRecentDocs(SHARD_PATHA, filepath)

            set_regkey_full(
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\12.0\\"
                "Word\\File MRU\\Item %d" % (idx + 1),
                "REG_SZ", "[F00000000][T01D1C40000000000]*%s" % filepath,
            )
