# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil
import logging

from rarfile import RarFile, BadRarFile

from lib.common.abstracts import Package
from lib.common.exceptions import CuckooPackageError

log = logging.getLogger(__name__)


class Rar(Package):
    """Rar analysis package."""

    def extract_rar(self, rar_path, extract_path, password):
        """Extracts a nested RAR file.
        @param rar_path: RAR path
        @param extract_path: where to extract
        @param password: RAR password
        """
        # Test if rar file contains a file named as itself.
        if self.is_overwritten(rar_path):
            log.debug("Rar file contains a file with the same name, "
                      "original is going to be overwrite")
            # TODO: add random string.
            new_rar_path = rar_path + ".old"
            shutil.move(rar_path, new_rar_path)
            rar_path = new_rar_path

        # Extraction.
        with RarFile(rar_path, "r") as archive:
            try:
                #for rarinfo in archive.infolist():
                #    try:
                #        rarinfo.filename = rarinfo.filename.decode('utf8').encode(sys.getfilesystemencoding())
                #    except UnicodeDecodeError:
                #        rarinfo.filename = rarinfo.filename.encode('utf8')
                #    archive.extract(rarinfo, path=extract_path, pwd=password)
                archive.extractall(path=extract_path, pwd=password)
            except BadRarFile:
                raise CuckooPackageError("Invalid Rar file")
            except RuntimeError:
                try:
                    archive.extractall(path=extract_path, pwd="infected")
                    #for rarinfo in archive.infolist():
                    #    try:
                    #        rarinfo.filename = rarinfo.filename.decode('utf8').encode('utf8')
                    #    except UnicodeDecodeError:
                    #        rarinfo.filename = rarinfo.filename.decode('cp866').encode('utf8')
                    #    archive.extract(rarinfo, path=extract_path,
                    #                    pwd="infected")
                except RuntimeError as e:
                    raise CuckooPackageError("Unable to extract Rar file: "
                                             "{0}".format(e))
            finally:
                # Extract nested archives.
                for name in archive.namelist():
                    if name.endswith(".rar"):
                        # Recurse.
                        self.extract_rar(os.path.join(extract_path, name),
                                         extract_path, password)

    def is_overwritten(self, rar_path):
        """Checks if the RAR file contains another file with the same name, so it is going to be overwritten.
        @param rar_path: Rar file path
        @return: comparison boolean
        """
        with RarFile(rar_path, "r") as archive:
            try:
                # Test if rar file contains a file named as itself.
                for name in archive.namelist():
                    if name == os.path.basename(rar_path):
                        return True
                return False
            except BadRarFile:
                raise CuckooPackageError("Invalid Rar file")

    def get_infos(self, rar_path):
        """Get information from RAR file.
        @param rar_path: rar file path
        @return: RarInfo class
        """
        try:
            with RarFile(rar_path, "r") as archive:
                #for rarinfo in archive.infolist():
                #    try:
                #        rarinfo.filename = rarinfo.filename.decode('utf8').encode('utf8')
                #    except UnicodeDecodeError:
                #        rarinfo.filename = rarinfo.filename.decode('cp866').encode('utf8')
                return archive.infolist()
        except BadRarFile:
            raise CuckooPackageError("Invalid Rar file")

    def start(self, path):
        password = self.options.get("password")

        rarinfos = self.get_infos(path)
        self.extract_rar(path, self.curdir, password)

        file_name = self.options.get("file")
        # If no file name is provided via option, take the first file.
        if not file_name:
            # No name provided try to find a better name.
            if len(rarinfos):
                # Take the first one.
                file_name = rarinfos[0].filename
                log.debug("Missing file option, auto executing: {0}".format(file_name.encode("utf8")))
            else:
                raise CuckooPackageError("Empty Rar archive")
        file_path = os.path.join(self.curdir, file_name)
        return self.execute(file_path, self.options.get("arguments"))
