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
    import magic
    IS_MAGIC = True
except ImportError, why:
    IS_MAGIC = False

class File:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_data = None

    def _get_md5(self):
        return hashlib.md5(self.file_data).hexdigest()

    def _get_sha1(self):
        return hashlib.sha1(self.file_data).hexdigest()

    def _get_sha256(self):
        return hashlib.sha256(self.file_data).hexdigest()

    def _get_sha512(self):
        return hashlib.sha512(self.file_data).hexdigest()

    def _get_type(self):
        if not IS_MAGIC:
            return None

        ms = magic.open(magic.MAGIC_NONE)
        ms.load()
        file_type = ms.buffer(self.file_data)

        return file_type

    def _get_size(self):
        return os.path.getsize(self.file_path)

    def process(self):
        if not os.path.exists(self.file_path):
            return None

        infos = {}

        self.file_data = open(self.file_path, "rb").read()
        infos["md5"]    = self._get_md5()
        infos["sha1"]   = self._get_sha1()
        infos["sha256"] = self._get_sha256()
        infos["sha512"] = self._get_sha512()
        infos["type"]   = self._get_type()
        infos["size"]   = self._get_size()

        return infos
