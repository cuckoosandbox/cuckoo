# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil
import tempfile

from cuckoo.common.files import Folders, Files, Storage
from cuckoo.common import utils

class TestCreateFolders:
    def setup(self):
        self.tmp_dir = tempfile.gettempdir()

    def test_root_folder(self):
        """Tests a single folder creation based on the root parameter."""
        Folders.create(os.path.join(self.tmp_dir, "foo"))
        assert os.path.exists(os.path.join(self.tmp_dir, "foo"))
        os.rmdir(os.path.join(self.tmp_dir, "foo"))

    def test_single_folder(self):
        """Tests a single folder creation."""
        Folders.create(self.tmp_dir, "foo")
        assert os.path.exists(os.path.join(self.tmp_dir, "foo"))
        os.rmdir(os.path.join(self.tmp_dir, "foo"))

    def test_multiple_folders(self):
        """Tests multiple folders creation."""
        Folders.create(self.tmp_dir, ["foo", "bar"])
        assert os.path.exists(os.path.join(self.tmp_dir, "foo"))
        assert os.path.exists(os.path.join(self.tmp_dir, "bar"))
        os.rmdir(os.path.join(self.tmp_dir, "foo"))
        os.rmdir(os.path.join(self.tmp_dir, "bar"))

    def test_duplicate_folder(self):
        """Tests a duplicate folder creation."""
        Folders.create(self.tmp_dir, "foo")
        assert os.path.exists(os.path.join(self.tmp_dir, "foo"))
        Folders.create(self.tmp_dir, "foo")
        os.rmdir(os.path.join(self.tmp_dir, "foo"))

    def test_delete_folder(self):
        """Tests folder deletion #1."""
        Folders.create(self.tmp_dir, "foo")
        assert os.path.exists(os.path.join(self.tmp_dir, "foo"))
        Folders.delete(os.path.join(self.tmp_dir, "foo"))
        assert not os.path.exists(os.path.join(self.tmp_dir, "foo"))

    def test_delete_folder2(self):
        """Tests folder deletion #2."""
        Folders.create(self.tmp_dir, "foo")
        assert os.path.exists(os.path.join(self.tmp_dir, "foo"))
        Folders.delete(self.tmp_dir, "foo")
        assert not os.path.exists(os.path.join(self.tmp_dir, "foo"))

    def test_create_temp(self):
        """Test creation of temporary directory."""
        dirpath1 = Folders.create_temp("/tmp")
        dirpath2 = Folders.create_temp("/tmp")
        assert os.path.exists(dirpath1)
        assert os.path.exists(dirpath2)
        assert dirpath1 != dirpath2

class TestCreateFile:
    def test_temp_file(self):
        filepath1 = Files.temp_put("hello", "/tmp")
        filepath2 = Files.temp_put("hello", "/tmp")
        assert open(filepath1, "rb").read() == "hello"
        assert open(filepath2, "rb").read() == "hello"
        assert filepath1 != filepath2
        os.unlink(filepath1)
        os.unlink(filepath2)

    def test_create(self):
        dirpath = tempfile.mkdtemp()
        Files.create(dirpath, "a.txt", "foo")
        assert open(os.path.join(dirpath, "a.txt"), "rb").read() == "foo"
        shutil.rmtree(dirpath)

    def test_named_temp(self):
        filepath = Files.temp_named_put("test", "hello.txt", "/tmp")
        assert open(filepath, "rb").read() == "test"
        assert os.path.basename(filepath) == "hello.txt"
        os.unlink(filepath)

class TestStorage:
    def test_basename(self):
        assert Storage.get_filename_from_path("C:\\a.txt") == "a.txt"
        assert Storage.get_filename_from_path("C:/a.txt") == "a.txt"
        # ???
        assert Storage.get_filename_from_path("C:\\\x00a.txt") == "\x00a.txt"

class TestConvertChar:
    def test_utf(self):
        assert "\\xe9", utils.convert_char(u"\xe9")

    def test_digit(self):
        assert "9" == utils.convert_char(u"9")

    def test_literal(self):
        assert "e" == utils.convert_char("e")

    def test_punctation(self):
        assert "." == utils.convert_char(".")

    def test_whitespace(self):
        assert " " == utils.convert_char(" ")

class TestConvertToPrintable:
    def test_utf(self):
        assert "\\xe9" == utils.convert_to_printable(u"\xe9")

    def test_digit(self):
        assert "9" == utils.convert_to_printable(u"9")

    def test_literal(self):
        assert "e" == utils.convert_to_printable("e")

    def test_punctation(self):
        assert "." == utils.convert_to_printable(".")

    def test_whitespace(self):
        assert " " == utils.convert_to_printable(" ")

    def test_non_printable(self):
        assert r"\x0b" == utils.convert_to_printable(chr(11))

class TestIsPrintable:
    def test_utf(self):
        assert not utils.is_printable(u"\xe9")

    def test_digit(self):
        assert utils.is_printable(u"9")

    def test_literal(self):
        assert utils.is_printable("e")

    def test_punctation(self):
        assert utils.is_printable(".")

    def test_whitespace(self):
        assert utils.is_printable(" ")

    def test_non_printable(self):
        assert not utils.is_printable(chr(11))

class TestVersiontuple:
    def test_version_tuple(self):
        assert (1, 1, 1, 0) == utils.versiontuple("1.1.1.0")

def test_version():
    from cuckoo import __version__
    from cuckoo.misc import version
    assert __version__ == version
