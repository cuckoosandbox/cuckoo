# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class APT_CloudAtlas(Signature):
    name = "apt_cloudatlas"
    description = "Creates known CloudAtlas APT files, registry keys and/or mutexes"
    severity = 3
    categories = ["apt"]
    families = ["cloudatlas"]
    authors = ["RedSocks"]
    minimum = "2.0"

    files_re = [
        ".*steinheimman",
        ".*papersaving",
        ".*previliges",
        ".*fundamentive",
        ".*bicorporate",
        ".*miditiming",
        ".*damnatorily",
        ".*munnopsis",
        ".*arzner",
        ".*redtailed",
        ".*roodgoose",
        ".*acholias",
        ".*salefians",
        ".*wartworts",
        ".*frequencyuse",
        ".*nonmagyar",
        ".*shebir",
        ".*getgoing",
    ]

    def on_complete(self):
        for indicator in self.files_re:
            for filepath in self.check_file(pattern=indicator, regex=True, all=True):
                self.mark_ioc("file", filepath)

        return self.has_marks()
