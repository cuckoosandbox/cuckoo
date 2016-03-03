# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class SDBot(Signature):
    name = "rat_sdbot"
    description = "Creates known SDBot Backdoor files, registry keys and/or mutexes"
    severity = 3
    categories = ["backdoor"]
    families = ["sdbot"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*Xq1MKTN4PE",
        ".*sdbot.*",
        "fixed",
        "RDBot2",
        "rdbot2",
        "dbot",
        "Dbot",
        "bot1",
        "rBot",
        "unitbots",
        "rXbot.*",
        "botid",
        "rdbot1",
        "RDBot",
        "rDbot.*",
        "RDBot.*",
        "rdbot.*",
        ".*Bitch.*-Bot.*",
        "GetTitleBarFileMutex",
    ]

    regkeys_re = [
        ".*h1Ucm.*",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            if self.check_mutex(pattern=indicator, regex=True):
                return True

        for indicator in self.regkeys_re:
            if self.check_key(pattern=indicator, regex=True):
                return True
