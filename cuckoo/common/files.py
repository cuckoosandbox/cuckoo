# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import hashlib
import tempfile
import ntpath
import shutil

from cuckoo.common.config import config
from cuckoo.common.exceptions import CuckooOperationalError

def temppath():
    """Returns the true temporary directory."""
    tmppath = config("cuckoo:cuckoo:tmppath")

    # Backwards compatibility with older configuration.
    if not tmppath or tmppath == "/tmp":
        return tempfile.gettempdir()

    return tmppath

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
    def create(root=".", folders=None):
        """Creates a directory or multiple directories.
        @param root: root path.
        @param folders: folders list to be created.
        @raise CuckooOperationalError: if fails to create folder.
        If folders is None, we try to create the folder provided by `root`.
        """
        if isinstance(root, (tuple, list)):
            root = os.path.join(*root)

        if folders is None:
            folders = [""]
        elif isinstance(folders, basestring):
            folders = folders,

        for folder in folders:
            folder_path = os.path.join(root, folder)
            if not os.path.isdir(folder_path):
                try:
                    os.makedirs(folder_path)
                except OSError:
                    raise CuckooOperationalError(
                        "Unable to create folder: %s" % folder_path
                    )

    @staticmethod
    def copy(src, dest):
        if os.path.exists(dest):
            shutil.rmtree(dest)
        shutil.copytree(src, dest)

    @staticmethod
    def create_temp(path=None):
        if path:
            target_path = path
        else:
            target_path = os.path.join(temppath(), "cuckoo-tmp")

        if not os.path.exists(target_path):
            os.mkdir(target_path)

        return tempfile.mkdtemp(dir=target_path)

    @staticmethod
    def delete(*folder):
        """Delete a folder and all its subdirectories.
        @param folder: path or components to path to delete.
        @raise CuckooOperationalError: if fails to delete folder.
        """
        folder = os.path.join(*folder)
        if os.path.exists(folder):
            try:
                shutil.rmtree(folder)
            except OSError:
                raise CuckooOperationalError(
                    "Unable to delete folder: %s" % folder
                )

class Files(Storage):
    @staticmethod
    def temp_put(content, path=None):
        """Store a temporary file or files.
        @param content: the content of this file
        @param path: directory path to store the file
        """
        if path:
            target_path = path
        else:
            target_path = os.path.join(temppath(), "cuckoo-tmp")

        if not os.path.exists(target_path):
            os.mkdir(target_path)

        fd, filepath = tempfile.mkstemp(prefix="upload_", dir=target_path)

        if hasattr(content, "read"):
            chunk = content.read(1024)
            while chunk:
                os.write(fd, chunk)
                chunk = content.read(1024)
        else:
            os.write(fd, content)

        os.close(fd)
        return filepath

    @staticmethod
    def temp_named_put(content, filename, path=None):
        """Store a named temporary file.
        @param content: the content of this file
        @param filename: filename that the file should have
        @param path: directory path to store the file
        @return: full path to the temporary file
        """
        if path:
            target_path = path
        else:
            target_path = os.path.join(temppath(), "cuckoo-tmp")

        if not os.path.exists(target_path):
            os.mkdir(target_path)

        filename = Storage.get_filename_from_path(filename)

        dirpath = tempfile.mkdtemp(dir=target_path)
        Files.create(dirpath, filename, content)
        return os.path.join(dirpath, filename)

    @staticmethod
    def create(root, filename, content):
        if isinstance(root, (tuple, list)):
            root = os.path.join(*root)

        filepath = os.path.join(root, filename)
        with open(filepath, "wb") as f:
            if hasattr(content, "read"):
                chunk = content.read(1024 * 1024)
                while chunk:
                    f.write(chunk)
                    chunk = content.read(1024 * 1024)
            else:
                f.write(content)
        return filepath

    @staticmethod
    def copy(path_target, path_dest):
        """Copy a file. The destination may be a directory.
        @param path_target: The
        @param path_dest: path_dest
        @return: path to the file or directory
        """
        shutil.copy(src=path_target, dst=path_dest)
        return os.path.join(path_dest, os.path.basename(path_target))

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

    @staticmethod
    def sha256_file(filepath):
        return Files.hash_file(hashlib.sha256, filepath)
