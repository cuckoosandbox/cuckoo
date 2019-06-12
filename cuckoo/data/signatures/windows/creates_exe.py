# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

try:
    import re2 as re
except ImportError:
    import re

class CreatesExe(Signature):
    name = "creates_exe"
    description = "Creates executable files on the filesystem"
    severity = 2
    categories = ["generic"]
    authors = ["Cuckoo Developers"]
    minimum = "2.0"
    ttp = ["T1129"]

    pattern = (
        ".*\\.(bat|cmd|com|cpl|dll|exe|js|jse|lnk|msi|msh|msh1|msh2|mshxml|"
        "msh1xml|msh2xml|ocx|pif|psc1|psc2|ps1|ps1xml|ps2|ps2xml|reg|scf|scr|"
        "vb|vbe|vbs|ws|wsc|wse|wsh)$"
    )

    def on_complete(self):
        for filepath in self.check_file(pattern=self.pattern, actions=["file_written"], regex=True, all=True):
            self.mark_ioc("file", filepath)

        return self.has_marks()

class CreatesUserFolderEXE(Signature):
    name = "creates_user_folder_exe"
    description = "Creates an executable file in a user folder"
    severity = 3
    families = ["persistance"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    ttp = ["T1129"]

    directories_re = [
        "^[a-zA-Z]:\\\\Users\\\\[^\\\\]+\\\\AppData\\\\.*",
        "^[a-zA-Z]:\\\\Documents\\ and\\ Settings\\\\[^\\\\]+\\\\Local\\ Settings\\\\.*",
    ]

    def on_complete(self):
        for dropped in self.get_results("dropped", []):
            if "filepath" in dropped:
                droppedtype = dropped["type"]
                filepath = dropped["filepath"]
                if "MS-DOS executable" in droppedtype:
                    for directory in self.directories_re:
                        if re.match(directory, filepath):
                            self.mark_ioc("file", filepath)

        return self.has_marks()
