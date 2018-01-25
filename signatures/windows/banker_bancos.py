# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class banker_bancos(Signature):
    name = "banker_bancos"
    description = "Creates known Bancos Banking Trojan files, registry keys and/or mutexes"
    severity = 3
    categories = ["trojan"]
    families = ["bancos"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        "MutexNPA_UnitVersioning_.*",
        "bS49LoZe35Hn",
        "6J8Ry37CAsG",
        "a7EKkWY7q6",
        "kqo0381T",
        "das0d7a98chasas89hb",
    ]

    files_re = [
        ".*sys32.*xsp",
        ".*003392B7.*",
        ".*Firefox34.*",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            if self.check_mutex(pattern=indicator, regex=True):
                return True

        for indicator in self.files_re:
            if self.check_file(pattern=indicator, regex=True):
                return True
