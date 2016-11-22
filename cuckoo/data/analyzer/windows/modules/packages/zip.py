# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil
import logging

from zipfile import ZipFile, BadZipfile

from lib.common.abstracts import Package
from lib.common.exceptions import CuckooPackageError

log = logging.getLogger(__name__)

class Zip(Package):
    """Zip analysis package."""

    def extract_zip(self, zip_path, extract_path, password):
        """Extracts a nested ZIP file.
        @param zip_path: ZIP path
        @param extract_path: where to extract
        @param password: ZIP password
        """
        # Test if zip file contains a file named as itself.
        if self.is_overwritten(zip_path):
            log.debug("ZIP file contains a file with the same name, original is going to be overwrite")
            # TODO: add random string.
            new_zip_path = zip_path + ".old"
            shutil.move(zip_path, new_zip_path)
            zip_path = new_zip_path

        # Extraction.
        with ZipFile(zip_path, "r") as archive:
            try:
                archive.extractall(path=extract_path, pwd=password)
            except BadZipfile:
                raise CuckooPackageError("Invalid Zip file")
            except RuntimeError:
                try:
                    archive.extractall(path=extract_path, pwd="infected")
                except RuntimeError as e:
                    raise CuckooPackageError("Unable to extract Zip file: "
                                             "{0}".format(e))
            finally:
                # Extract nested archives.
                for name in archive.namelist():
                    if name.endswith(".zip"):
                        # Recurse.
                        self.extract_zip(os.path.join(extract_path, name), extract_path, password)

    def is_overwritten(self, zip_path):
        """Checks if the ZIP file contains another file with the same name, so it is going to be overwritten.
        @param zip_path: zip file path
        @return: comparison boolean
        """
        with ZipFile(zip_path, "r") as archive:
            try:
                # Test if zip file contains a file named as itself.
                for name in archive.namelist():
                    if name == os.path.basename(zip_path):
                        return True
                return False
            except BadZipfile:
                raise CuckooPackageError("Invalid Zip file")

    def get_infos(self, zip_path):
        """Get information from ZIP file.
        @param zip_path: zip file path
        @return: ZipInfo class
        """
        try:
            with ZipFile(zip_path, "r") as archive:
                return archive.infolist()
        except BadZipfile:
            raise CuckooPackageError("Invalid Zip file")

    def start(self, path):
        password = self.options.get("password")

        zipinfos = self.get_infos(path)
        self.extract_zip(path, self.curdir, password)

        file_name = self.options.get("file")
        # If no file name is provided via option, take the first file.
        if not file_name:
            # No name provided try to find a better name.
            if len(zipinfos):
                # Take the first one.
                file_name = zipinfos[0].filename
                log.debug("Missing file option, auto executing: {0}".format(file_name))
            else:
                raise CuckooPackageError("Empty ZIP archive")

        file_path = os.path.join(self.curdir, file_name)
        return self.execute(file_path, self.options.get("arguments"))
