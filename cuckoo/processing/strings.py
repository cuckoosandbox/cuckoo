# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import floss
import os.path
import re
import vivisect

from cuckoo.common.abstracts import Processing
from cuckoo.common.exceptions import CuckooProcessingError
from floss import identification_manager as id_man
from floss import main
from floss import stackstrings
from floss import strings as static

class Strings(Processing):
    """Extract encoded & static strings from analyzed file with """
    MAX_FILESIZE = 16*1024*1024
    MAX_STRINGCNT = 2048
    MAX_STRINGLEN = 1024
    MIN_STRINGLEN = 4

    def run(self):
        """Run floss on analyzed file.
        @return: floss results dict.
        """
        self.key = "strings"
        strings = {}

        STRING_TYPES = [
            "decoded",
            "stack",
            "static"
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

            # Prepare FLOSS for extracting hidden & encoded strings
            vw = vivisect.VivWorkspace()
            vw.loadFromFile(self.file_path)
            vw.analyze()

            selected_functions = main.select_functions(vw, None)
            decoding_functions_candidates = id_man.identify_decoding_functions(
                vw, main.get_all_plugins(), selected_functions
            )

            # Decode & extract hidden & encoded strings
            decoded_strings = main.decode_strings(
                vw, decoding_functions_candidates, self.MIN_STRINGLEN
            )
            for i, str in enumerate(decoded_strings):
                decoded_strings[i] = main.sanitize_string_for_printing(str.s)

            stack_strings = []
            stack_strs = stackstrings.extract_stackstrings(
                vw, selected_functions, self.MIN_STRINGLEN
            )
            for str in stack_strs:
                stack_strings.append(str.s)

            # Extract static strings
            static_strings = []
            for str in static.extract_ascii_strings(data, self.MIN_STRINGLEN):
                static_strings.append(str.s)

            for str in static.extract_unicode_strings(data, self.MIN_STRINGLEN):
                static_strings.append(str.s)

            results = [decoded_strings, stack_strings, static_strings]

            for i, str_type in enumerate(STRING_TYPES):
                strings[str_type] = results[i]

        return strings
