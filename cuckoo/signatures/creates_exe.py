# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cuckoo.common.abstracts import Signature

class CreatesExe(Signature):
    name = "creates_exe"
    description = "Creates a Windows executable on the filesystem"
    severity = 2
    categories = ["generic"]
    authors = ["Cuckoo Developers"]
    minimum = "2.0"

    # This is a signature template. It should be used as a skeleton for
    # creating custom signatures, therefore is disabled by default.
    # It doesn't verify whether a .exe is actually being created, but
    # it matches files being opened with any access type, including
    # read and attributes lookup.
    enabled = False

    def on_complete(self):
        match = self.check_file(pattern=".*\\.exe$", regex=True)
        if match:
            self.mark_ioc("file", match)
            return True
