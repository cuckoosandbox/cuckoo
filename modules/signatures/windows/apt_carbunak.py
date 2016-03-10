# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class APT_Carbunak(Signature):
    name = "apt_carbunak"
    description = "Creates known Carbunak/Anunak APT files, registry keys and/or mutexes"
    severity = 3
    categories = ["apt"]
    families = ["carbunak"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*Uw1HDFMKPAlFRFYZ.*",
        ".*VVpHVlcJbQtFQVNP.*",
        ".*BAgXCgAIbQtFFwRP.*",
        ".*WApFWgRebQtFRFZP.*",
        ".*VlxDV1lSbQtFTVdP.*",
        ".*AwxMCwcIbQtFTQBP.*",
        ".*UghMW1BbbQtFRlNP.*",
        ".*Vl5FCABfbQtFRQNP.*",
        ".*Vg9GC1FbbQtFQlRP.*",
        ".*BQ9EXgBbbQtFF1RP.*",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            for mutex in self.check_mutex(pattern=indicator, regex=True, all=True):
                self.mark_ioc("mutex", mutex)

        return self.has_marks()
