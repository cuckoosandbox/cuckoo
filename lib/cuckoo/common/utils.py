import os
import sys
import string
import logging
import hashlib
import binascii

try:
    import magic
except ImportError:
    pass

try:
    import ssdeep
    HAVE_SSDEEP = True
except ImportError, why:
    HAVE_SSDEEP = False

def create_folders(root=".", folders=[]):
    for folder in folders:
        if os.path.exists(folder):
            continue

        try:
            folder_path = os.path.join(root, folder)
            os.makedirs(folder_path)
        except OSError as e:
            continue

def convert_char(c):
    if c in string.ascii_letters or \
       c in string.digits or \
       c in string.punctuation or \
       c in string.whitespace:
        return c
    else:
        return r'\x%02x' % ord(c)

def convert_to_printable(s):
    return ''.join([convert_char(c) for c in s])

class File:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_data = open(self.file_path, "rb").read()

    def get_name(self):
        return convert_to_printable(os.path.basename(self.file_path))

    def get_size(self):
        return os.path.getsize(self.file_path)

    def get_crc32(self):
        res = ''
        crc = binascii.crc32(self.file_data)
        for i in range(4):
            t = crc & 0xFF
            crc >>= 8
            res = '%02X%s' % (t, res) 
        return res

    def get_md5(self):
        return hashlib.md5(self.file_data).hexdigest()

    def get_sha1(self):
        return hashlib.sha1(self.file_data).hexdigest()

    def get_sha256(self):
        return hashlib.sha256(self.file_data).hexdigest()

    def get_sha512(self):
        return hashlib.sha512(self.file_data).hexdigest()

    def get_ssdeep(self):
        if not HAVE_SSDEEP:
            return None

        try:
            return ssdeep.ssdeep().hash_file(self.file_path)
        except Exception, why:
            return None

    def get_type(self):
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
