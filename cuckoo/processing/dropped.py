# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import os

from cuckoo.common.abstracts import Processing
from cuckoo.common.objects import File

class Dropped(Processing):
    """Dropped files analysis."""

    def run(self):
        """Run analysis.
        @return: list of dropped files with related information.
        """
        self.key = "dropped"
        dropped_files, meta = [], {}

        if os.path.exists(self.dropped_meta_path):
            for line in open(self.dropped_meta_path, "rb"):
                entry = json.loads(line)
                filepath = os.path.join(self.analysis_path, entry["path"])
                meta[filepath] = {
                    "pids": entry["pids"],
                    "filepath": entry["filepath"],
                }

        for dir_name, dir_names, file_names in os.walk(self.dropped_path):
            for file_name in file_names:
                file_path = os.path.join(dir_name, file_name)
                file_info = File(file_path=file_path).get_all()
                file_info.update(meta.get(file_info["path"], {}))
                dropped_files.append(file_info)

        for dir_name, dir_names, file_names in os.walk(self.package_files):
            for file_name in file_names:
                file_path = os.path.join(dir_name, file_name)
                file_info = File(file_path=file_path).get_all()
                dropped_files.append(file_info)

        return dropped_files
