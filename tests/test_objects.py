# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import pytest
import tempfile

from cuckoo.common.objects import Dictionary, File

class TestDictionary:
    def setup_method(self, method):
        self.d = Dictionary()

    def test_usage(self):
        self.d.a = "foo"
        assert "foo" == self.d.a
        self.d.a = "bar"
        assert "bar" == self.d.a

    def test_exception(self):
        with pytest.raises(AttributeError):
            self.d.b.a

class TestFile:
    def setup(self):
        self.path = tempfile.mkstemp()[1]
        self.file = File(self.path)

    def test_get_name(self):
        assert self.path.split("/")[-1] == self.file.get_name()

    def test_get_data(self):
        assert "" == self.file.get_data()

    def test_get_size(self):
        assert 0 == self.file.get_size()

    def test_get_crc32(self):
        assert "00000000" == self.file.get_crc32()

    def test_get_md5(self):
        assert "d41d8cd98f00b204e9800998ecf8427e" == self.file.get_md5()

    def test_get_sha1(self):
        assert "da39a3ee5e6b4b0d3255bfef95601890afd80709" == self.file.get_sha1()

    def test_get_sha256(self):
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" == self.file.get_sha256()

    def test_get_sha512(self):
        assert "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" == self.file.get_sha512()

    def test_get_ssdeep(self):
        try:
            import pydeep
            assert self.file.get_ssdeep() is not None
            pydeep  # Fake usage.
        except ImportError:
            assert self.file.get_ssdeep() is None

    def test_get_type(self):
        assert "empty " == self.file.get_type()

    def test_get_content_type(self):
        assert self.file.get_content_type() in ["inode/x-empty", "application/x-empty"]

    def test_get_all_type(self):
        assert isinstance(self.file.get_all(), dict)

    def test_get_all_keys(self):
        for key in ["name", "size", "crc32", "md5", "sha1", "sha256", "sha512", "ssdeep", "type"]:
            assert key in self.file.get_all()

    def teardown(self):
        os.remove(self.path)
