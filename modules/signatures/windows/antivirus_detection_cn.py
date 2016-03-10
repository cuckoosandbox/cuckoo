# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AVDetectionChinaKey(Signature):
    name = "av_detect_china_key"
    description = "Checks for known Chinese AV sofware registry keys"
    severity = 2
    categories = ["avdetect"]
    families = ["china"]
    authors = ["RedSocks"]
    minimum = "2.0"

    indicators = [
        ".*360Safe",
        ".*rising",
        ".*Kingsoft",
        ".*JiangMin",
    ]

    def on_complete(self):
        for indicator in self.indicators:
            for regkey in self.check_key(pattern=indicator, regex=True, all=True):
                self.mark_ioc("regkey", indicator)

        return self.has_marks()
