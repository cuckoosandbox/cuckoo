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

        file_path = os.path.join(root, self.options.get("file", "sample.exe"))
        free = self.options.get("free", False)
        args = self.options.get("arguments", None)
        suspended = True
        if free:
            suspended = False

        p = Process()
        if not p.execute(path=file_path, args=args, suspended=suspended):
            raise CuckooPackageError("Unable to execute initial process, analysis aborted")

        if not free and suspended:
            p.inject()
            p.resume()
            return p.pid
        else:
            return None

    def check(self):
        return True

    def finish(self):
        return True
