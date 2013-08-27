# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import hashlib
import binascii
import logging

try:
    import magic
except ImportError:
    pass

try:
    import pydeep
    HAVE_SSDEEP = True
except ImportError:
    HAVE_SSDEEP = False

try:
    import yara
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False

from lib.cuckoo.common.constants import CUCKOO_ROOT

log = logging.getLogger(__name__)

FILE_CHUNK_SIZE = 16 * 1024

class Dictionary(dict):
    """Cuckoo custom dict."""

    def __getattr__(self, key):
        return self.get(key, None)

    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

class URL:
    """URL base object."""

    def __init__(self, url):
        """@param url: URL"""
        self.url = url

class File:
    """Basic file object class with all useful utilities."""

    def __init__(self, file_path):
        """@param file_path: file path."""
        self.file_path = file_path

        # these will be populated when first accessed
        self._file_data = None
        self._crc32     = None
        self._md5       = None
        self._sha1      = None
        self._sha256    = None
        self._sha512    = None

    def get_name(self):
        """Get file name.
        @return: file name.
        """
        file_name = os.path.basename(self.file_path)
        return file_name

    def valid(self):
        return os.path.exists(self.file_path) and \
            os.path.isfile(self.file_path) and \
            os.path.getsize(self.file_path) != 0

    def get_data(self):
        """Read file contents.
        @return: data.
        """
        return self.file_data

    def get_chunks(self):
        """Read file contents in chunks (generator)."""

        fd = open(self.file_path, "rb")
        while True:
            chunk = fd.read(FILE_CHUNK_SIZE)
            if not chunk: break
            yield chunk
        fd.close()

    def calc_hashes(self):
        """Calculate all possible hashes for this file."""
        crc     = 0
        md5     = hashlib.md5()
        sha1    = hashlib.sha1()
        sha256  = hashlib.sha256()
        sha512  = hashlib.sha512()
        
        for chunk in self.get_chunks():
            crc = binascii.crc32(chunk, crc)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)

        self._crc32     = "".join("%02X" % ((crc>>i)&0xff) for i in [24, 16, 8, 0])
        self._md5       = md5.hexdigest()
        self._sha1      = sha1.hexdigest()
        self._sha256    = sha256.hexdigest()
        self._sha512    = sha512.hexdigest()

    @property
    def file_data(self):
        log.warning("Usage of File.file_data is deprecated, use chunks of files only.")
        if not self._file_data: self._file_data = open(self.file_path, "rb").read()
        return self._file_data

    def get_size(self):
        """Get file size.
        @return: file size.
        """
        return os.path.getsize(self.file_path)

    def get_crc32(self):
        """Get CRC32.
        @return: CRC32.
        """
        if not self._crc32: self.calc_hashes()
        return self._crc32

    def get_md5(self):
        """Get MD5.
        @return: MD5.
        """
        if not self._md5: self.calc_hashes()
        return self._md5

    def get_sha1(self):
        """Get SHA1.
        @return: SHA1.
        """
        if not self._sha1: self.calc_hashes()
        return self._sha1

    def get_sha256(self):
        """Get SHA256.
        @return: SHA256.
        """
        if not self._sha256: self.calc_hashes()
        return self._sha256

    def get_sha512(self):
        """
        Get SHA512.
        @return: SHA512.
        """
        if not self._sha512: self.calc_hashes()
        return self._sha512

    def get_ssdeep(self):
        """Get SSDEEP.
        @return: SSDEEP.
        """
        if not HAVE_SSDEEP:
            return None

        try:
            return pydeep.hash_file(self.file_path)
        except Exception:
            return None

    def get_type(self):
        """Get MIME file type.
        @return: file type.
        """
        try:
            ms = magic.open(magic.MAGIC_NONE)
            ms.load()
            file_type = ms.file(self.file_path)
        except:
            try:
                file_type = magic.from_file(self.file_path)
            except:
                try:
                    import subprocess
                    file_process = subprocess.Popen(["file",
                                                     "-b",
                                                     self.file_path],
                                                    stdout = subprocess.PIPE)
                    file_type = file_process.stdout.read().strip()
                except:
                    return ""
        finally:
            try:
                ms.close()
            except:
                pass

        return file_type

    def get_yara(self, rulepath=os.path.join(CUCKOO_ROOT, "data", "yara", "index_binary.yar")):
        """Get Yara signatures matches.
        @return: matched Yara signatures.
        """
        matches = []

        if HAVE_YARA and os.path.getsize(self.file_path) > 0:
            try:
                rules = yara.compile(rulepath)

                for match in rules.match(self.file_path):
                    strings = []
                    for s in match.strings:
                        # Beware, spaghetti code ahead.
                        try:
                            new = s[2].encode("utf-8")
                        except UnicodeDecodeError:
                            s = s[2].lstrip("uU").encode("hex").upper()
                            s = " ".join(s[i:i+2] for i in range(0, len(s), 2))
                            new = "{ %s }" % s

                        if new not in strings:
                            strings.append(new)

                    matches.append({"name" : match.rule,
                                    "meta" : match.meta,
                                    "strings" : strings})
            except yara.Error as e:
                log.warning("Unable to match Yara signatures: %s", e)

        return matches

    def get_all(self):
        """Get all information available.
        @return: information dict.
        """
        infos = {}
        infos["name"] = self.get_name()
        infos["path"] = self.file_path
        infos["size"] = self.get_size()
        infos["crc32"] = self.get_crc32()
        infos["md5"] = self.get_md5()
        infos["sha1"] = self.get_sha1()
        infos["sha256"] = self.get_sha256()
        infos["sha512"] = self.get_sha512()
        infos["ssdeep"] = self.get_ssdeep()
        infos["type"] = self.get_type()
        infos["yara"] = self.get_yara()

        return infos
