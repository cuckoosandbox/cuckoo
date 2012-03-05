# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2012  Claudio "nex" Guarnieri (nex@cuckoobox.org)
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
import logging
import hashlib
import binascii

from cuckoo.common.stringutils import convert_to_printable

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
    """
    Generate information regarding the specified file.
    """
    
    def __init__(self, file_path):
        """
        Creates a new instance
        @param file_path: path to file
        """ 
        self.file_path = file_path
        self.file_data = None

    def _get_name(self):
        """
        Retrieves the original file name of the file.
        @return: file name
        """
        return convert_to_printable(os.path.basename(self.file_path))

    def _get_size(self):
        """
        Retrieves the size of the file expressed in bytes.
        @return: file size
        """
        return os.path.getsize(self.file_path)

    def _get_crc32(self):
        """
        Generates the CRC32 hash of the file.
        @return: CRC32 hash of the file
        """
        res = ''
        crc = binascii.crc32(self.file_data)
        for i in range(4):
            t = crc & 0xFF
            crc >>= 8
            res = '%02X%s' % (t, res) 
        return res

    def _get_md5(self):
        """
        Generates the MD5 hash of the file.
        @return: MD5 hash of the file
        """
        return hashlib.md5(self.file_data).hexdigest()

    def _get_sha1(self):
        """
        Generates the SHA-1 hash of the file.
        @return: SHA-1 hash of the file
        """
        return hashlib.sha1(self.file_data).hexdigest()

    def _get_sha256(self):
        """
        Generates the SHA-256 hash of the file.
        @return: SHA-256 hash of the file
        """
        return hashlib.sha256(self.file_data).hexdigest()

    def _get_sha512(self):
        """
        Generates the SHA-512 hash of the file.
        @return: SHA-512 hash of the file
        """
        return hashlib.sha512(self.file_data).hexdigest()

    def _get_ssdeep(self):
        """
        Generates the ssdeep fuzzy hash of the file.
        @return: ssdeep fuzzy hash of the file
        """
        log = logging.getLogger("Processing.File")
        
        if not IS_SSDEEP:
            log.warning("Ssdeep Python bindings are not installed, " \
                        "skipping fuzzy hash of file \"%s\"." % self.file_path)
            return None

        try:
            return ssdeep.ssdeep().hash_file(self.file_path)
        except Exception, why:
            log.warning("Something went wrong while generating ssdeep hash " \
                        "for file at path \"%s\": %s" % (self.file_path, why))
            return None

    def _get_type(self):
        """
        Retrieves the libmagic type of the file.
        @return: file type
        """
        log = logging.getLogger("Processing.File")
        
        if not IS_MAGIC:
            log.warning("Libmagic Python bindings are not installed, " \
                        "skipping file type of file \"%s\"." % self.file_path)
            return None

        try:
            ms = magic.open(magic.MAGIC_NONE)
            ms.load()
            file_type = ms.buffer(self.file_data)
        except:
            try:
                file_type = magic.from_buffer(self.file_data)
            except Exception, why:
                log.warning("Something went wrong while retrieving magic for file \"%s\": %s"
                            % (self.file_path, why))
                return None
        
        return file_type

    def process(self):
        """
        Generates file information dictionary.
        @return: dictionary containing all the file's information
        """
        log = logging.getLogger("Processing.File")
        
        if not os.path.exists(self.file_path):
            log.error("File at path \"%s\" does not exist." % self.file_path)
            return None

        self.file_data = open(self.file_path, "rb").read()

        infos = {}
        infos["name"]   = self._get_name()
        infos["size"]   = self._get_size()
        infos["crc32"]  = self._get_crc32()
        infos["md5"]    = self._get_md5()
        infos["sha1"]   = self._get_sha1()
        infos["sha256"] = self._get_sha256()
        infos["sha512"] = self._get_sha512()
        infos["ssdeep"] = self._get_ssdeep()
        infos["type"]   = self._get_type()

        return infos
