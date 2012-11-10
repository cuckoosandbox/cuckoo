# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
from zipfile import ZipFile, BadZipfile

from lib.common.abstracts import Package
from lib.common.exceptions import CuckooPackageError
from lib.api.process import Process

class Zip(Package):
    """Zip analysis package."""

    def start(self, path):
        root = os.environ["TEMP"]

        with ZipFile(path, "r") as archive:
            try:
                archive.extractall(root)
            except BadZipfile as e:
                raise CuckooPackageError("Invalid Zip file")
            except RuntimeError:
                try:
                    archive.extractall(path=root, pwd="infected")
                except RuntimeError as e:
                    raise CuckooPackageError("Unable to extract Zip file, unknown password?")

        if "file" in self.options:
            file_path = os.path.join(root, self.options["file"])
        else:
            file_path = os.path.join(root, "sample.exe")

        p = Process()
        p.execute(path=file_path, suspended=True)
        p.inject()
        p.resume()

        return p.pid

    def check(self):
        return True

    def finish(self):
        return True
