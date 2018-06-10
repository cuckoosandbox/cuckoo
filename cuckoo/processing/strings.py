# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path
import re
import floss
import vivisect

from cuckoo.common.abstracts import Processing
from cuckoo.common.exceptions import CuckooProcessingError

class Strings(Processing):
    """Extract encoded & static strings from analyzed file with floss."""
    MAX_FILESIZE = 16*1024*1024
    MAX_STRINGCNT = 2048
    MAX_STRINGLEN = 1024
    MIN_STRINGLEN = 4

    def run(self):
        """Run floss on analyzed file.
        @return: floss results dict.
        """
        self.key = "strings"
        recovered_strings = {}

        STRING_TYPES = [
            "acsii",
            "utf16",
            "decoded",
            "stack"
        ]

        if self.task["category"] == "file":
            if not os.path.exists(self.file_path):
                raise CuckooProcessingError(
                    "Sample file doesn't exist: \"%s\"" % self.file_path
                )

            try:
                data = open(self.file_path, "r").read(self.MAX_FILESIZE)
            except (IOError, OSError) as e:
                raise CuckooProcessingError("Error opening file %s" % e)

            # Extract static strings
            acsii_strings = floss.strings.extract_ascii_strings(
                data,
                self.MIN_STRINGLEN
            )
            uft16_strings = floss.strings.extract_unicode_strings(
                data,
                self.MIN_STRINGLEN
            )

            # Prepare FLOSS for extracting hidden & encoded strings
            vw = vivisect.VivWorkspace()
            vw.loadFromFile(self.file_path)
            vw.analyze()

            selected_functions = floss.main.select_functions(vw, None)
            decoding_functions_candidates = floss.identification_manager.identify_decoding_functions(
                vw,
                floss.main.get_all_plugins(),
                selected_functions
            )

            # Decode & extract hidden & encoded strings
            decoded_strings = floss.main.decode_strings(
                vw,
                decoding_functions_candidates,
                self.MIN_STRINGLEN
            )
            stack_strings = floss.stackstrings.extract_stackstrings(
                vw,
                selected_functions,
                self.MIN_STRINGLEN
            )

        # Now limit the amount & length of the strings.
        results = [acsii_strings, uft16_strings, decoded_strings, stack_strings]
        for strings in results:
            strings = strings[:self.MAX_STRINGCNT]
            for idx, s in enumerate(strings):
                strings[idx] = s[:self.MAX_STRINGLEN]

        for i in len(STRING_TYPES):
            recovered_strings[STRING_TYPES[i]] = results[i]

        return recovered_strings
