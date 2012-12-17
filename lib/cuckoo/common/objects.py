# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import hashlib
import binascii
import itertools
import collections
from datetime import datetime

try:
    import magic
except ImportError:
    pass

try:
    import pydeep
    HAVE_SSDEEP = True
except ImportError:
    HAVE_SSDEEP = False

from lib.cuckoo.common.utils import convert_to_printable

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

    def __init__(self, file_path, strip_name=False):
        """@param file_path: file path."""
        self.file_path = file_path
        self.file_data = open(self.file_path, "rb").read()
        self.strip_name = strip_name

    def get_name(self):
        """Get file name.
        @return: file name.
        """
        if self.strip_name:
            file_name = os.path.basename(self.file_path.rstrip(".bin"))
        else:
            file_name = os.path.basename(self.file_path)

        return file_name

    def get_data(self):
        """Read file contents.
        @return: data.
        """
        return self.file_data

    def get_size(self):
        """Get file size.
        @return: file size.
        """
        return os.path.getsize(self.file_path)

    def get_crc32(self):
        """Get CRC32.
        @return: CRC32.
        """
        res = ''
        crc = binascii.crc32(self.file_data)
        for i in range(4):
            t = crc & 0xFF
            crc >>= 8
            res = '%02X%s' % (t, res)
        return res

    def get_md5(self):
        """Get MD5.
        @return: MD5.
        """
        return hashlib.md5(self.file_data).hexdigest()

    def get_sha1(self):
        """Get SHA1.
        @return: SHA1.
        """
        return hashlib.sha1(self.file_data).hexdigest()

    def get_sha256(self):
        """Get SHA256.
        @return: SHA256.
        """
        return hashlib.sha256(self.file_data).hexdigest()

    def get_sha512(self):
        """
        Get SHA512.
        @return: SHA512.
        """
        return hashlib.sha512(self.file_data).hexdigest()

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
            file_type = ms.buffer(self.file_data)
        except:
            try:
                file_type = magic.from_buffer(self.file_data)
            except:
                try:
                    import subprocess
                    file_process = subprocess.Popen(['file',
                                                     '-b',
                                                     self.file_path],
                                                    stdout = subprocess.PIPE)
                    file_type = file_process.stdout.read().strip()
                except:
                    return None
        finally:
            try:
                ms.close()
            except:
                pass

        return file_type

    def get_all(self):
        """Get all information available.
        @return: information dict.
        """
        infos = {}
        infos["name"] = self.get_name()
        infos["size"] = self.get_size()
        infos["crc32"] = self.get_crc32()
        infos["md5"] = self.get_md5()
        infos["sha1"] = self.get_sha1()
        infos["sha256"] = self.get_sha256()
        infos["sha512"] = self.get_sha512()
        infos["ssdeep"] = self.get_ssdeep()
        infos["type"] = self.get_type()

        return infos


class LocalDict(collections.MutableMapping, dict):
    """Dictionary with local-only mutable slots.
    Useful for reporting / signatures which try to change
    our precious result data structure.
    """

    def __init__(self, origdict):
        self.orig = origdict
        self.local = dict()

    def __getitem__(self, attr):
        if attr in self.local:
            return self.local[attr]
        return self.orig[attr]

    def __setitem__(self, attr, value):
        self.local[attr] = value

    def __delitem__(self, attr):
        return self.local[attr]

    def __iter__(self):
        return itertools.chain(iter(self.orig), iter(self.local))

    def __len__(self):
        return len(self.orig) + len(self.local)
