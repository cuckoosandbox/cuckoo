# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.objects import File
from lib.cuckoo.common.abstracts import Processing

class FileAnalysis(Processing):
    """General information about a file."""

    def run(self):
        """Run file information gathering.
        @return: information dict.
        """
        self.key = "file"
        file_info = File(self.file_path).get_all()
        file_info["name"] = self.cfg.analysis.file_name
        return file_info
