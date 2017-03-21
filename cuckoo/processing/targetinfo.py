# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path

from cuckoo.common.abstracts import Processing
from cuckoo.common.objects import File

class TargetInfo(Processing):
    """General information about a file."""

    def run(self):
        """Run file information gathering.
        @return: information dict.
        """
        self.key = "target"
        if not self.task:
            return {
                "category": "unknown",
                "file": {
                    "name": "unknown",
                },
            }

        ret = {
            "category": self.task["category"],
        }

        # We have to deal with file, archive, and URL targets.
        if self.task["category"] == "file":
            ret["file"] = {}

            # Let's try to get as much information as possible, i.e., the
            # filename if the file is not available anymore.
            if os.path.exists(self.file_path):
                ret["file"] = File(self.file_path).get_all()

            ret["file"]["name"] = File(self.task["target"]).get_name()
        elif self.task["category"] == "archive":
            ret["archive"] = File(self.file_path).get_all()
            ret["archive"]["name"] = File(self.task["target"]).get_name()
            ret["filename"] = self.task["options"]["filename"]
            ret["human"] = "%s @ %s" % (
                ret["filename"], ret["archive"]["name"]
            )
        elif self.task["category"] == "url":
            ret["url"] = self.task["target"]

        return ret
