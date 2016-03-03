# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import tempfile
from nose.tools import assert_equal, raises, assert_not_equal
from lib.cuckoo.common.objects import File

import lib.cuckoo.common.utils as utils
from lib.cuckoo.common.exceptions import CuckooOperationalError


class TestCreateFolders:
    def setUp(self):
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
    def setUp(self):
        self.tmp_dir = tempfile.gettempdir()

    def test_single_folder(self):
        """Tests a single folder creation."""
        utils.create_folder(self.tmp_dir, "foo")
        assert os.path.exists(os.path.join(self.tmp_dir, "foo"))
        utils.create_folder(self.tmp_dir, "foo")
        os.rmdir(os.path.join(self.tmp_dir, "foo"))

class TestConvertChar:
    def test_utf(self):
        assert_equal("\\xe9", utils.convert_char(u"\xe9"))

    def test_digit(self):
        assert_equal("9", utils.convert_char(u"9"))

    def test_literal(self):
        assert_equal("e", utils.convert_char("e"))

    def test_punctation(self):
        assert_equal(".", utils.convert_char("."))

    def test_whitespace(self):
        assert_equal(" ", utils.convert_char(" "))

class TestConvertToPrintable:
    def test_utf(self):
        assert_equal("\\xe9", utils.convert_to_printable(u"\xe9"))

    def test_digit(self):
        assert_equal("9", utils.convert_to_printable(u"9"))

    def test_literal(self):
        assert_equal("e", utils.convert_to_printable("e"))

    def test_punctation(self):
        assert_equal(".", utils.convert_to_printable("."))

    def test_whitespace(self):
        assert_equal(" ", utils.convert_to_printable(" "))

    def test_non_printable(self):
        assert_equal(r"\x0b", utils.convert_to_printable(chr(11)))

class TestDatetimeToIso:
    def test_convert_date(self):
        assert_equal("2000-01-01T11:43:35", utils.datetime_to_iso("2000-01-01 11:43:35"))

class TestFile:
    def setUp(self):
        self.tmp = tempfile.mkstemp()
        self.file = File(self.tmp[1])

    def test_get_name(self):
        assert_equal(self.tmp[1].split("/")[-1], self.file.get_name())

    def test_get_data(self):
        assert_equal("", self.file.get_data())

    def test_get_size(self):
        assert_equal(0, self.file.get_size())

    def test_get_crc32(self):
        assert_equal("00000000", self.file.get_crc32())

    def test_get_md5(self):
        assert_equal("d41d8cd98f00b204e9800998ecf8427e", self.file.get_md5())

    def test_get_sha1(self):
        assert_equal("da39a3ee5e6b4b0d3255bfef95601890afd80709", self.file.get_sha1())

    def test_get_sha256(self):
        assert_equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", self.file.get_sha256())

    def test_get_sha512(self):
        assert_equal("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", self.file.get_sha512())

    def test_get_ssdeep(self):
        try:
            import pydeep
            assert_not_equal(None, self.file.get_ssdeep())
        except ImportError:
            assert_equal(None, self.file.get_ssdeep())

    def test_get_type(self):
        assert_equal("empty", self.file.get_type())

    def test_get_all_type(self):
        assert isinstance(self.file.get_all(), dict)

    def test_get_all_keys(self):
        for key in ["name", "size", "crc32", "md5", "sha1", "sha256", "sha512", "ssdeep", "type"]:
            assert key in self.file.get_all()

    def tearDown(self):
        os.remove(self.tmp[1])
