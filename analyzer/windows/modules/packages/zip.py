# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
from zipfile import ZipFile, BadZipfile

from lib.common.abstracts import Package
from lib.common.exceptions import CuckooPackageError

class Zip(Package):
    """Zip analysis package."""

    def start(self, path):
        root = os.environ["TEMP"]
        password = self.options.get("password")

        with ZipFile(path, "r") as archive:
            try:
                zipinfos = archive.infolist()
                archive.extractall(path=root, pwd=password)
            except BadZipfile:
                raise CuckooPackageError("Invalid Zip file")
            except RuntimeError:
                try:
                    archive.extractall(path=root, pwd="infected")
                except RuntimeError as e:
                    raise CuckooPackageError("Unable to extract Zip file: "
                                             "{0}".format(e))

        file_name = self.options.get("file")
        # If no file name is provided via option, take the first file.
        if not file_name:
            # No name provided try to find a better name.
            if len(zipinfos):
                # Take the first one.
                file_name = zipinfos[0].filename
            else:
                raise CuckooPackageError("Empty ZIP archive")

        file_path = os.path.join(root, file_name)
        return self.execute(file_path, self.options.get("arguments"))
