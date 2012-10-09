# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.objects import File
from lib.cuckoo.common.abstracts import Processing

class TargetInfo(Processing):
    """General information about a file."""

    def run(self):
        """Run file information gathering.
        @return: information dict.
        """
        self.key = "target"

        target_info = {"category" : self.cfg.analysis.category}

        if self.cfg.analysis.category == "file":
            target_info["file"] = File(self.file_path).get_all()
            target_info["file"]["name"] = self.cfg.analysis.file_name
        elif self.cfg.analysis.category == "url":
            target_info["url"] = self.cfg.analysis.target

        return target_info