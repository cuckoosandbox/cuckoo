# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class WinSCP(Signature):
    name = "mutex_winscp"
    description = "WinSCP Files, Registry Keys and/or Mutexes Detected"
    severity = 3
    categories = ["filetransfer"]
    families = ["winscp"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        "WinSCP",
    ]

    files_re = [
        ".*winscp.*",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            if self.check_mutex(pattern=indicator, regex=True):
                return True

        for indicator in self.files_re:
            if self.check_file(pattern=indicator, regex=True):
                return True
