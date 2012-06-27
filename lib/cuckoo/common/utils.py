# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import string
import logging
import hashlib
import binascii
from datetime import datetime

try:
    import magic
except ImportError:
    pass

try:
    import ssdeep
    HAVE_SSDEEP = True
except ImportError:
    HAVE_SSDEEP = False

def create_folders(root=".", folders=[]):
    """Create direcotry.
    @param root: root path.
    @param folders: folders name to be created.
    """
    for folder in folders:
        if os.path.exists(os.path.join(root, folder)):
            continue

        try:
            folder_path = os.path.join(root, folder)
            os.makedirs(folder_path)
        except OSError as e:
            continue

def convert_char(c):
    """Escapes characters.
    @param c: dirty char.
    @return: sanitized char.
    """
    if c in string.ascii_letters or \
       c in string.digits or \
       c in string.punctuation or \
       c in string.whitespace:
        return c
    else:
        return r'\x%02x' % ord(c)

def convert_to_printable(s):
    """Convert char to printable.
    @param s: string.
    @return: sanitized string.
    """
    return ''.join([convert_char(c) for c in s])

def datetime_to_iso(timestamp):
    """Parse a datatime string and returns a datetime in iso format.
    @param timestamp: timestamp string
    @return: ISO datetime
    """  
    if hasattr(datetime, 'strptime'):
        # Python 2.6
        strptime = datetime.strptime
    else:
        # Python 2.4 equivalent
        import time
        strptime = lambda date_string, format: datetime(*(time.strptime(date_string, format)[0:6]))
    return strptime(timestamp, '%Y-%m-%d %H:%M:%S').isoformat()

class File:
    """Basic file object class with all useful utilities."""

    def __init__(self, file_path):
        """@param file_path: file path."""
        self.file_path = file_path
        self.file_data = open(self.file_path, "rb").read()

    def get_name(self):
        """Get file name.
        @return: file name.
        """
        return convert_to_printable(os.path.basename(self.file_path))

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
            return ssdeep.ssdeep().hash_file(self.file_path)
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
                    file_process = subprocess.Popen(['file', '-b', self.file_path], stdout = subprocess.PIPE)
                    file_type = file_process.stdout.read().strip()
                except:
                    return None

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
