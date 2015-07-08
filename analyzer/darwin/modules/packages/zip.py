#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This file is part of my GSoC'15 project for Cuckoo Sandbox:
#	http://www.cuckoosandbox.org
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import logging
from shutil import move
from subprocess import check_output
from os import path, environ, system
from zipfile import ZipFile, BadZipfile
from lib.core.packages import Package, choose_package_class

log = logging.getLogger(__name__)

class Zip(Package):

    def prepare(self):
        password = self.options.get("password")
        files = self._extract(self.target, password)
        if not files or len(files) == 0:
            raise Exception("Invalid (or empty) zip archive: %s" % self.target)
        # Look for a file to analyse
        target_name = self.options.get("file")
        if not target_name:
            # If no file name is provided via option, take the first file
            target_name = files[0]
            log.debug("Missing file option, auto executing: {0}".format(target_name))

        # Since we don't know what kind of file we're going to analyse, let's
        # detect it automatically and create an appropriate analysis package
        # for this file
        self.target = path.join(environ.get("TEMP", "/tmp"), target_name)
        file_info = self._fileinfo(self.target)
        pkg_class = choose_package_class(file_info, target_name)

        if not pkg_class:
            raise Exception("Unable to detect analysis package for the file %s" % target_name)
        else:
            log.debug("Analysing file \"%s\" using package \"%s\"", target_name,
                pkg_class.__name__)

        kwargs = {
            "options" : self.options,
            "timeout" : self.timeout
        }
        # We'll forward start() method invocation to the proper package later
        self.real_package = pkg_class(self.target, self.host, **kwargs)

    def start(self):
        # We have nothing to do here; let other package do it's job
        self.prepare()
        self.real_package.start()

    def _fileinfo(self, file):
        o = check_output(["file", file])
        return o[o.index(":")+2:]

    def _extract(self, file, password):
        # Verify that the archive is actually readable
        if not self._verify_archive(file):
            return None
        # Test if zip file contains a file named as itself.
        if self._is_overwritten(file):
            log.debug("ZIP file contains a file with the same name, original is going to be overwrite")
            # TODO: add random string.
            new_zip_path = file + ".old"
            move(file, new_zip_path)
            file = new_zip_path
        # Extraction.
        extract_path = environ.get("TEMP", "/tmp")
        with ZipFile(file, "r") as archive:
            try:
                archive.extractall(path=extract_path, pwd=password)
            except BadZipfile:
                raise Exception("Invalid Zip file")
            # Try to extract it again, but with a default password
            except RuntimeError:
                try:
                    archive.extractall(path=extract_path, pwd="infected")
                except RuntimeError as e:
                    raise Exception("Unable to extract Zip file: {0}".format(e))
            finally:
                # Extract nested archives
                for name in archive.namelist():
                    if name.endswith(".zip"):
                        self._extract(os.path.join(extract_path, name), password)
        return archive.namelist()

    def _verify_archive(self, path):
        try:
            with ZipFile(path, "r") as archive:
                return True
        except BadZipfile:
            return False

    def _is_overwritten(self, zip_path):
        with ZipFile(zip_path, "r") as archive:
            try:
                # Test if zip file contains a file named as itself
                for name in archive.namelist():
                    if name == path.basename(zip_path):
                        return True
                return False
            except BadZipfile:
                raise Exception("Invalid Zip file")
