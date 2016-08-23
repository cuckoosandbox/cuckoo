# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import tempfile

from cuckoo.common import utils

class TestCreateFolders:
    def setup(self):
        self.tmp_dir = tempfile.gettempdir()

    def test_single_folder(self):
        """Tests a single folder creation."""
        utils.create_folders(self.tmp_dir, ["foo"])
        assert os.path.exists(os.path.join(self.tmp_dir, "foo"))
        os.rmdir(os.path.join(self.tmp_dir, "foo"))

    def test_multiple_folders(self):
        """Tests multiple folders creation."""
        utils.create_folders(self.tmp_dir, ["foo", "bar"])
        assert os.path.exists(os.path.join(self.tmp_dir, "foo"))
        assert os.path.exists(os.path.join(self.tmp_dir, "bar"))
        os.rmdir(os.path.join(self.tmp_dir, "foo"))
        os.rmdir(os.path.join(self.tmp_dir, "bar"))

class TestCreateFolder:
    def setup(self):
        self.tmp_dir = tempfile.gettempdir()

    def test_single_folder(self):
        """Tests a single folder creation."""
        utils.create_folder(self.tmp_dir, "foo")
        assert os.path.exists(os.path.join(self.tmp_dir, "foo"))
        utils.create_folder(self.tmp_dir, "foo")
        os.rmdir(os.path.join(self.tmp_dir, "foo"))

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
