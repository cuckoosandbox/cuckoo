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
import magic
import hashlib

class File:
    def __init__(self, file_path):
        self.file_path = file_path
        self.infos = {}

    def _get_md5(self):
        data = open(self.file_path, "rb").read()
        return hashlib.md5(data).hexdigest()

    def _get_sha1(self):
        data = open(self.file_path, "rb").read()
        return hashlib.sha1(data).hexdigest()

    def _get_sha256(self):
        data = open(self.file_path, "rb").read()
        return hashlib.sha256(data).hexdigest()

    def _get_type(self):
        ms = magic.open(magic.MAGIC_NONE)
        ms.load()
        data = open(self.file_path, "rb").read()
        file_type = ms.buffer(data)

        return file_type

    def _get_size(self):
        return os.path.getsize(self.file_path)

    def process(self):
        if not os.path.exists(self.file_path):
            # XXX Add error msg
            return None

        self.infos["md5"]    = self._get_md5()
        self.infos["sha1"]   = self._get_sha1()
        self.infos["sha256"] = self._get_sha256()
        self.infos["type"]   = self._get_type()
        self.infos["size"]   = self._get_size()

        return self.infos
