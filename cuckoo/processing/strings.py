# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path
import re
import vivisect

from cuckoo.common.abstracts import Processing
from cuckoo.common.exceptions import CuckooProcessingError
from cuckoo.common.objects import File

from floss import identification_manager as id_man
from floss import main
from floss import stackstrings
from floss import strings as static

class Strings(Processing):
    """Extract encoded & static strings from analyzed file with Floss"""
    def run(self):
        """Run Floss on analyzed file.
        @return: Floss results dict.
        """
        self.key = "strings"
        self.floss = self.options.get("floss")
        self.MIN_STRINGLEN = int(self.options.get("min_str_len"))
        self.MAX_STRINGLEN = self.options.get("max_str_len")
        self.MAX_STRINGCNT = self.options.get("max_str_cnt")
        self.idapro = self.options.get("idapro_str_sct")
        self.radare = self.options.get("radare_str_sct")
        self.x64dbg = self.options.get("x64dbg_str_sct")
        self.MAX_FILESIZE = 16*1024*1024
        
        STRING_TYPES = [
            "decoded",
            "stack",
            "static"
        ]
        
        strings = {}

        if self.task["category"] == "file":
            if not os.path.exists(self.file_path):
                raise CuckooProcessingError(
                    "Sample file doesn't exist: \"%s\"" % self.file_path
                )

            try:
                f = File(self.file_path)
                filename = os.path.basename(self.task["target"])
                base_name = os.path.splitext(filename)[0]
                ext = filename.split(os.path.extsep)[-1].lower()
                data = open(self.file_path, "r").read(self.MAX_FILESIZE)
            except (IOError, OSError) as e:
                raise CuckooProcessingError("Error opening file %s" % e)
            
            # Extract static strings
            static_strings = re.findall("[\x1f-\x7e]{" + str(self.MIN_STRINGLEN) + ",}", data)
            for s in re.findall("(?:[\x1f-\x7e][\x00]){" + str(self.MIN_STRINGLEN) + ",}", data):
                static_strings.append(s.decode("utf-16le"))

            if self.MAX_STRINGLEN != 0:
                for i, s in enumerate(static_strings):
                    static_strings[i] = s[:self.MAX_STRINGLEN]

            if self.MAX_STRINGCNT != 0 and len(static_strings) > self.MAX_STRINGCNT:
                static_strings = static_strings[:self.MAX_STRINGCNT]
                static_strings.append("[snip]")

            package = self.task.get("package")

            if self.floss and (package == "exe" or ext == "exe" or "PE32" in f.get_type()):
                # Disable floss verbose logging
                main.set_logging_levels()
                
                try:
                    # Prepare Floss for extracting hidden & encoded strings
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
                    decoded_strs = main.filter_unique_decoded(decoded_strings)

                    stack_strings = stackstrings.extract_stackstrings(
                        vw, selected_functions, self.MIN_STRINGLEN
                    )
                    stack_strings = list(stack_strings)

                    decoded_strings = [x for x in decoded_strs if not x in static_strings]
                except Exception as e:
                    raise CuckooProcessingError("Error extracting strings with floss: %s" % e)

                if len(decoded_strings) or len(stack_strings):
                    # Create annotated scripts
                    if self.idapro:
                        main.create_ida_script(
                            self.file_path, os.path.join(self.str_script_path, base_name + ".idb"),
                            decoded_strings, stack_strings, True
                        )

                    if self.radare:
                        main.create_r2_script(
                            self.file_path, os.path.join(self.str_script_path, base_name + ".r2"),
                            decoded_strings, stack_strings, True
                        )

                    if self.x64dbg:
                        imagebase = vw.filemeta.values()[0]['imagebase']
                        main.create_x64dbg_database(
                            self.file_path, os.path.join(self.str_script_path, base_name + ".json"),
                            imagebase, decoded_strings, True
                        )

                # convert Floss strings into regular, readable strings
                for idx, s in enumerate(decoded_strings):
                    decoded_strings[idx] = main.sanitize_string_for_printing(s.s)

                for idx, s in enumerate(stack_strings):
                    stack_strings[idx] = s.s

                results = [decoded_strings, stack_strings, static_strings]

                for idx, str_type in enumerate(STRING_TYPES):
                    strings[str_type] = results[idx]

            else:
                strings["static"] = static_strings

        return strings
