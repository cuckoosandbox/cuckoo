# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import hashlib
import tempfile
import ntpath
import shutil

from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.common.config import Config

class Storage(object):
    @staticmethod
    def get_filename_from_path(path):
        """Cross-platform filename extraction from path.
        @param path: file path.
        @return: filename.
        """
        dirpath, filename = ntpath.split(path)
        return filename if filename else ntpath.basename(dirpath)

class Folders(Storage):
    @staticmethod
    def create(root=".", folder="", folders=[]):
        """Creates a directory or multiple directories.
        @param root: root path.
        @param folder: folder name to be created.
        @param folders: folders list to be created.
        @raise CuckooOperationalError: if fails to create folder.
        """
        if folder and isinstance(folder, (str, unicode)) and folder not in folders:
            folders.append(folder)

        folder_path = os.path.join(root, folder)
        for folder in folders:
            if folder and not os.path.isdir(folder_path):
                try:
                    os.makedirs(folder_path)
                except OSError:
                    raise CuckooOperationalError("Unable to create folder: %s" %
                                                 folder_path)

    @staticmethod
    def delete(folder):
        """Delete a folder and all its subdirectories.
        @param folder: path to delete.
        @raise CuckooOperationalError: if fails to delete folder.
        """
        if os.path.exists(folder):
            try:
                shutil.rmtree(folder)
            except OSError:
                raise CuckooOperationalError("Unable to delete folder: "
                                             "{0}".format(folder))

class Files(Storage):
    @staticmethod
    def tmp_put(file=None, files=[], path=None):
        """Store a temporary file or files.
        @TO-DO: Make abstract tmp. storage class
        @param files: a list of dicts containing 'name' and 'data'
        @param path: optional path for temp directory.
        @return: path to the temporary file.
        """
        if file:
            files.append(file)

        options = Config()

        # Create temporary directory path.
        if path:
            target_path = path
        else:
            tmp_path = options.cuckoo.get("tmppath", "/tmp")
            target_path = os.path.join(tmp_path, "cuckoo-tmp")
        if not os.path.exists(target_path):
            os.mkdir(target_path)

        tmp_dir = tempfile.mkdtemp(prefix="upload_", dir=target_path)
        for f in files:
            filename = Storage.get_filename_from_path(f["name"])
            tmp_file_path = os.path.join(tmp_dir, filename)
            with open(tmp_file_path, "wb") as tmp_file:
                # If filedata is file object, do chunked copy.
                if hasattr(f["data"], "read"):
                    chunk = f["data"].read(1024)
                    while chunk:
                        tmp_file.write(chunk)
                        chunk = f["data"].read(1024)
                else:
                    tmp_file.write(f["data"])

        return tmp_dir

    @staticmethod
    def hash_file(method, filepath):
        """Calculates an hash on a file by path.
        @param method: callable hashing method
        @param path: file path
        @return: computed hash string
        """
        f = open(filepath, "rb")
        h = method()
        while True:
            buf = f.read(1024 * 1024)
            if not buf:
                break
            h.update(buf)
        return h.hexdigest()

    @staticmethod
    def md5_file(filepath):
        return Files.hash_file(hashlib.md5, filepath)

    @staticmethod
    def sha1_file(filepath):
        return Files.hash_file(hashlib.sha1, filepath)
