# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class VirtualPCDetect(Signature):
    name = "antivm_virtualpc"
    description = "Tries to detect VirtualPC"
    severity = 3
    categories = ["anti-vm"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    mutexes_re = [
        ".*MicrosoftVirtualPC7UserServiceMakeSureWe'reTheOnlyOneMutex",
    ]

    dlls_re = [
        ".*vpc-s3\\.sys$",
        ".*vpcubus\\.sys$",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            for mutex in self.check_mutex(pattern=indicator, regex=True, all=True):
                self.mark_ioc("mutex", mutex)

        for indicator in self.dlls_re:
            for filepath in self.check_file(pattern=indicator, regex=True, all=True):
                self.mark_ioc("file", filepath)

            for dll in self.check_dll_loaded(pattern=indicator, regex=True, all=True):
                self.mark_ioc("dll", dll)

        return self.has_marks()
