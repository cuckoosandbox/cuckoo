# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path
import re

from cuckoo.common.abstracts import Processing
from cuckoo.common.exceptions import CuckooProcessingError

class Strings(Processing):
    """Extract strings from analyzed file."""
    MAX_FILESIZE = 16*1024*1024
    MAX_STRINGCNT = 2048
    MAX_STRINGLEN = 1024

    def run(self):
        """Run extract of printable strings.
        @return: list of printable strings.
        """
        self.key = "strings"
        strings = []

        if self.task["category"] == "file":
            if not os.path.exists(self.file_path):
                raise CuckooProcessingError(
                    "Sample file doesn't exist: \"%s\"" % self.file_path
                )

            try:
                data = open(self.file_path, "r").read(self.MAX_FILESIZE)
            except (IOError, OSError) as e:
                raise CuckooProcessingError("Error opening file %s" % e)

            strings = re.findall("[\x1f-\x7e]{6,}", data)
            for s in re.findall("(?:[\x1f-\x7e][\x00]){6,}", data):
                strings.append(s.decode("utf-16le"))

        # Now limit the amount & length of the strings.
        strings = strings[:self.MAX_STRINGCNT]
        for idx, s in enumerate(strings):
            strings[idx] = s[:self.MAX_STRINGLEN]

        return strings
