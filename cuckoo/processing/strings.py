# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path
import vivisect

from cuckoo.common.abstracts import Processing
from cuckoo.common.exceptions import CuckooProcessingError
from cuckoo.common.objects import File
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
                f = File(self.file_path)
                filename = os.path.basename(self.task["target"])
                ext = filename.split(os.path.extsep)[-1].lower()
                data = open(self.file_path, "r").read(self.MAX_FILESIZE)
            except (IOError, OSError) as e:
                raise CuckooProcessingError("Error opening file %s" % e)

            # Extract static strings
            static_strings = []
            for str in static.extract_ascii_strings(data, self.MIN_STRINGLEN):
                static_strings.append(str.s[:self.MAX_STRINGLEN])

            for str in static.extract_unicode_strings(data, self.MIN_STRINGLEN):
                static_strings.append(str.s[:self.MAX_STRINGLEN])

            if len(static_strings) > self.MAX_STRINGCNT:
                static_strings = static_strings[:self.MAX_STRINGCNT]
                static_strings.append("[snip]")

            package = self.task.get("package")

            if package == "exe" or ext == "exe" or "PE32" in f.get_type():
                try:
                    # Prepare FLOSS for extracting hidden & encoded strings
                    vw = vivisect.VivWorkspace()
                    vw.loadFromFile(self.file_path)
                    vw.analyze()

                    selected_functions = main.select_functions(vw, None)
                    decoding_functions_candidates = id_man.identify_decoding_functions(
                        vw, main.get_all_plugins(), selected_functions
                    )
                except Exception as e:
                    raise CuckooProcessingError("Error analyzing file with vivisect: %s" % e)

                try:
                    # Decode & extract hidden & encoded strings
                    decoded_strings = main.decode_strings(
                        vw, decoding_functions_candidates, self.MIN_STRINGLEN
                    )

                    stack_strs = stackstrings.extract_stackstrings(
                        vw, selected_functions, self.MIN_STRINGLEN
                    )
                except Exception as e:
                    raise CuckooProcessingError("Error extracting strings with floss: %s" % e)

                for i, str in enumerate(decoded_strings):
                    decoded_strings[i] = main.sanitize_string_for_printing(str.s)
                    
                uniq_decoded_strings = [x for x in decoded_strings if not x in static_strings]

                stack_strings = []
                for str in stack_strs:
                    stack_strings.append(str.s)

                results = [uniq_decoded_strings, stack_strings, static_strings]

                for i, str_type in enumerate(STRING_TYPES):
                    strings[str_type] = results[i]

            else:
                strings["static"] = static_strings

        return strings
