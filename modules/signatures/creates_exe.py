# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class CreatesExe(Signature):
    name = "creates_exe"
    description = "Creates a Windows executable on the filesystem"
    severity = 2
    categories = ["generic"]
    authors = ["Cuckoo Developers"]
    minimum = "0.5"

    # This is a signature template. It should be used as a skeleton for
    # creating custom signatures, therefore is disabled by default.
    # It doesn't verify whether a .exe is actually being created, but
    # it matches files being opened with any access type, including
    # read and attributes lookup.
    enabled = False

    def run(self):
        match = self.check_file(pattern=".*\\.exe$",
                                regex=True)
        if match:
            self.data.append({"file": match})
            return True

        return False
