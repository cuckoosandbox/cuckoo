# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import re

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.exceptions import CuckooProcessingError

class DroppedBuffer(Processing):
    """Dropped buffer analysis."""

    def run(self):
        """Run analysis.
        @return: list of dropped files with related information.
        """
        self.key = "buffer"
        dropped_files, meta = [], {}

        for dir_name, dir_names, file_names in os.walk(self.buffer_path):
            for file_name in file_names:
                file_path = os.path.join(dir_name, file_name)
                file_info = File(file_path=file_path).get_all()

                try:
                    data = open(file_path, "r").read()
                except (IOError, OSError) as e:
                    raise CuckooProcessingError("Error opening file %s" % e)
                strings = re.findall("[\x1f-\x7e]{6,}", data)
                strings += [str(ws.decode("utf-16le")) for ws in
                            re.findall("(?:[\x1f-\x7e][\x00]){6,}", data)]

                meta[file_path] = {
                    "filename": file_name,
                    "strings": strings,
                }

                file_info.update(meta.get(file_info["path"], {}))
                dropped_files.append(file_info)

        return dropped_files
