# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class FakeAVMutexes(Signature):
    name = "fakeav_mutexes"
    description = "Creates known FakeAV/FakeSysDef Mutexes"
    severity = 3
    categories = ["rat"]
    families = ["fakeav"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*83a5f83b-5aa7-4fa7-bbf5-63829add296e",
        ".*9cf2592c-1832-4358-a0fc-26d6a0c29808",
        ".*d8bb5910-2d85-489b-8403-803ed25e73bc",
        ".*86e8a495-357c-437c-b6e9-13e757bfabab",
        ".*Malware\\ Protection_MUTEX",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            mutex = self.check_mutex(pattern=indicator, regex=True)
            if mutex:
                self.mark_ioc("mutex", mutex)

        return self.has_marks()
