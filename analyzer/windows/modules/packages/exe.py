# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shlex

from lib.common.abstracts import Package

class Exe(Package):
    """EXE analysis package."""

    REGKEYS = [
        [
            HKEY_LOCAL_MACHINE,
            "Software\\Microsoft\\Security Center",
            {
                # "Would you like Internet Explorer as default browser?"
                "Check_Associations": "no",

                # "Set Up Windows Internet Explorer 8"
                "DisableFirstRunCustomize": 1,

                ### added
                "NoProtectedModeBanner": 1,
                "NoUpdateCheck": 1,
                "Start Page": "about:blank",
                "Enable Browser Extensions": "yes",
                "DoNotTrack": 0,
                "NoProtectedModeBanner": 1,
            },
        ],
    ]

    def start(self, path):
        args = self.options.get("arguments", "")

        name, ext = os.path.splitext(path)
        if not ext:
            new_path = name + ".exe"
            os.rename(path, new_path)
            path = new_path

        return self.execute(path, args=shlex.split(args))
