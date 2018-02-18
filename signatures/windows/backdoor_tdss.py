# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class TDSSBackdoor(Signature):
    name = "backdoor_tdss"
    description = "Creates known TDSS Backdoor files, registry keys and/or mutexes"
    severity = 3
    categories = ["backdoor"]
    families = ["tdss"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*TdlStartMutex"
    ]

    files_re = [
        ".*TDSS.*tmp",
    ]

    regkeys_re = [
        ".*TDSSserv.*",
        ".*tdssdata.*",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            if self.check_mutex(pattern=indicator, regex=True):
                return True

        for indicator in self.files_re:
            if self.check_file(pattern=indicator, regex=True):
                return True

        for indicator in self.regkeys_re:
            if self.check_key(pattern=indicator, regex=True):
                return True
