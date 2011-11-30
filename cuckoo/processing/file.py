#!/usr/bin/python
# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2011  Claudio "nex" Guarnieri (nex@cuckoobox.org)
# http://www.cuckoobox.org
#
# This file is part of Cuckoo.
#
# Cuckoo is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Cuckoo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.

import os
import sys
import hashlib

try:
    # Try to import libmagic python bindings. You can install them with Ubuntu's
    # python-magic package.
    import magic
    IS_MAGIC = True
except ImportError, why:
    IS_MAGIC = False

try:
    # Try to import Jose's pyssdeep bindings.
    # You can get them at http://code.google.com/p/pyssdeep/
    import ssdeep
    IS_SSDEEP = True
except ImportError, why:
    IS_SSDEEP = False

class File:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_data = None

    def _get_name(self):
        return os.path.basename(self.file_path)

    def _get_size(self):
        return os.path.getsize(self.file_path)

    def _get_md5(self):
        return hashlib.md5(self.file_data).hexdigest()

    def _get_sha1(self):
        return hashlib.sha1(self.file_data).hexdigest()

    def _get_sha256(self):
        return hashlib.sha256(self.file_data).hexdigest()

    def _get_sha512(self):
        return hashlib.sha512(self.file_data).hexdigest()

    def _get_ssdeep(self):
        if not IS_SSDEEP:
            return None

        try:
            return ssdeep.ssdeep().hash_file(self.file_path)
        except:
            return None

    def _get_type(self):
        if not IS_MAGIC:
            return None

        try:
            ms = magic.open(magic.MAGIC_NONE)
            ms.load()
            return ms.buffer(self.file_data)
        except:
            return None

    def process(self):
        if not os.path.exists(self.file_path):
            return None

        self.file_data = open(self.file_path, "rb").read()

        infos = {}
        infos["name"]   = self._get_name()
        infos["size"]   = self._get_size()
        infos["md5"]    = self._get_md5()
        infos["sha1"]   = self._get_sha1()
        infos["sha256"] = self._get_sha256()
        infos["sha512"] = self._get_sha512()
        infos["ssdeep"] = self._get_ssdeep()
        infos["type"]   = self._get_type()

        return infos
