# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import cStringIO
import hashlib
import io
import mock
import os
import pytest
import shutil
import tempfile

import cuckoo

from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.common.files import Folders, Files, Storage, temppath
from cuckoo.common.whitelist import is_whitelisted_domain
from cuckoo.common import utils
from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd, getuser

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

    def test_copy_folder(self):
        """Tests recursive folder copy"""
        dirpath = tempfile.mkdtemp()
        set_cwd(dirpath)

        Folders.copy("tests/files/sample_analysis_storage", dirpath)
        assert os.path.isfile("%s/reports/report.json" % dirpath)

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
        dirpath1 = Folders.create_temp()
        dirpath2 = Folders.create_temp()
        assert os.path.exists(dirpath1)
        assert os.path.exists(dirpath2)
        assert dirpath1 != dirpath2

    def test_create_temp_conf(self):
        """Test creation of temporary directory with configuration."""
        dirpath = tempfile.mkdtemp()
        set_cwd(dirpath)

        Folders.create(dirpath, "conf")
        with open(os.path.join(dirpath, "conf", "cuckoo.conf"), "wb") as f:
            f.write("[cuckoo]\ntmppath = %s" % dirpath)

        dirpath2 = Folders.create_temp()
        assert dirpath2.startswith(dirpath)

    @pytest.mark.skipif("sys.platform != 'linux2'")
    def test_create_invld_linux(self):
        """Test creation of a folder we can't access."""
        with pytest.raises(CuckooOperationalError):
            Folders.create("/invalid/directory")

    @pytest.mark.skipif("sys.platform != 'win32'")
    def test_create_invld_windows(self):
        """Test creation of a folder we can't access."""
        with pytest.raises(CuckooOperationalError):
            Folders.create("Z:\\invalid\\directory")

    def test_delete_invld(self):
        """Test deletion of a folder we can't access."""
        dirpath = tempfile.mkdtemp()

        os.chmod(dirpath, 0)
        with pytest.raises(CuckooOperationalError):
            Folders.delete(dirpath)

        os.chmod(dirpath, 0775)
        Folders.delete(dirpath)

    def test_create_tuple(self):
        dirpath = tempfile.mkdtemp()
        Folders.create(dirpath, "a")
        Folders.create((dirpath, "a"), "b")
        Files.create((dirpath, "a", "b"), "c.txt", "nested")

        filepath = os.path.join(dirpath, "a", "b", "c.txt")
        assert open(filepath, "rb").read() == "nested"

class TestCreateFile:
    def test_temp_file(self):
        filepath1 = Files.temp_put("hello")
        filepath2 = Files.temp_put("hello")
        assert open(filepath1, "rb").read() == "hello"
        assert open(filepath2, "rb").read() == "hello"
        assert filepath1 != filepath2

    def test_create(self):
        dirpath = tempfile.mkdtemp()
        Files.create(dirpath, "a.txt", "foo")
        assert open(os.path.join(dirpath, "a.txt"), "rb").read() == "foo"
        shutil.rmtree(dirpath)

    def test_named_temp(self):
        filepath = Files.temp_named_put("test", "hello.txt")
        assert open(filepath, "rb").read() == "test"
        assert os.path.basename(filepath) == "hello.txt"

    def test_named_temp_rel(self):
        filepath = Files.temp_named_put("test", "../foobar/hello.txt")
        assert open(filepath, "rb").read() == "test"
        assert "foobar" not in filepath

    def test_named_temp_abs(self):
        filepath = Files.temp_named_put("test", "/tmp/foobar/hello.txt")
        assert open(filepath, "rb").read() == "test"
        assert "foobar" not in filepath

    def test_temp_conf(self):
        dirpath = tempfile.mkdtemp()
        set_cwd(dirpath)

        Folders.create(dirpath, "conf")
        with open(os.path.join(dirpath, "conf", "cuckoo.conf"), "wb") as f:
            f.write("[cuckoo]\ntmppath = %s" % dirpath)

        filepath = Files.temp_put("foo")
        assert filepath.startswith(dirpath)

    def test_stringio(self):
        filepath = Files.temp_put(cStringIO.StringIO("foo"))
        assert open(filepath, "rb").read() == "foo"

    def test_bytesio(self):
        filepath = Files.temp_put(io.BytesIO("foo"))
        assert open(filepath, "rb").read() == "foo"

    def test_create_bytesio(self):
        dirpath = tempfile.mkdtemp()
        filepath = Files.create(dirpath, "a.txt", io.BytesIO("A"*1024*1024))
        assert open(filepath, "rb").read() == "A"*1024*1024

    def test_hash_file(self):
        filepath = Files.temp_put("hehe")
        assert Files.md5_file(filepath) == "529ca8050a00180790cf88b63468826a"
        assert Files.sha1_file(filepath) == "42525bb6d3b0dc06bb78ae548733e8fbb55446b3"
        assert Files.sha256_file(filepath) == "0ebe2eca800cf7bd9d9d9f9f4aafbc0c77ae155f43bbbeca69cb256a24c7f9bb"

    def test_create_tuple(self):
        dirpath = tempfile.mkdtemp()
        Folders.create(dirpath, "foo")
        Files.create((dirpath, "foo"), "a.txt", "bar")

        filepath = os.path.join(dirpath, "foo", "a.txt")
        assert open(filepath, "rb").read() == "bar"

    def test_fd_exhaustion(self):
        fd, filepath = tempfile.mkstemp()

        for x in xrange(0x100):
            Files.temp_put("foo")

        fd2, filepath = tempfile.mkstemp()

        # Let's leave a bit of working space.
        assert fd2 - fd < 64

class TestStorage:
    def test_basename(self):
        assert Storage.get_filename_from_path("C:\\a.txt") == "a.txt"
        assert Storage.get_filename_from_path("C:/a.txt") == "a.txt"
        assert Storage.get_filename_from_path("C:\\\x00a.txt") == "\x00a.txt"
        assert Storage.get_filename_from_path("/tmp/a.txt") == "a.txt"
        assert Storage.get_filename_from_path("../../b.txt") == "b.txt"
        assert Storage.get_filename_from_path("..\\..\\c.txt") == "c.txt"

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

def test_version():
    from cuckoo import __version__
    from cuckoo.misc import version
    assert __version__ == version

def test_exception():
    s = utils.exception_message()
    assert "Cuckoo version: %s" % cuckoo.__version__ in s
    assert "alembic:" in s
    assert "django-extensions:" in s
    assert "peepdf:" in s
    assert "sflock:" in s

def test_guid():
    assert utils.guid_name("{0002e005-0000-0000-c000-000000000046}") == "InprocServer32"
    assert utils.guid_name("{13709620-c279-11ce-a49e-444553540000}") == "Shell"

def test_jsbeautify():
    js = {
        "if(1){a(1,2,3);}": "if (1) {\n    a(1, 2, 3);\n}",
    }
    for k, v in js.items():
        assert utils.jsbeautify(k) == v

@mock.patch("cuckoo.common.utils.jsbeautifier")
def test_jsbeautify_packer(p, capsys):
    def beautify(s):
        print u"error: Unknown p.a.c.k.e.r. encoding.\n",

    p.beautify.side_effect = beautify
    utils.jsbeautify("thisisjavascript")
    out, err = capsys.readouterr()
    assert not out and not err

def test_jsbeautifier_exception():
    buf = open("tests/files/jsbeautifier1.js", "rb").read()
    assert utils.jsbeautify(buf) == buf

def test_htmlprettify():
    html = {
        "<a href=google.com>wow</a>": '<a href="google.com">\n wow\n</a>',
    }
    for k, v in html.items():
        assert utils.htmlprettify(k) == v

def test_temppath():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    assert temppath() == os.path.join(
        tempfile.gettempdir(), "cuckoo-tmp-%s" % getuser()
    )

    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "cuckoo": {
            "cuckoo": {
                "tmppath": "",
            },
        },
    })
    assert temppath() == os.path.join(
        tempfile.gettempdir(), "cuckoo-tmp-%s" % getuser()
    )

    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "cuckoo": {
            "cuckoo": {
                "tmppath": "/tmp",
            },
        },
    })
    assert temppath() == os.path.join(
        tempfile.gettempdir(), "cuckoo-tmp-%s" % getuser()
    )

    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "cuckoo": {
            "cuckoo": {
                "tmppath": "/custom/directory",
            },
        },
    })
    assert temppath() == "/custom/directory"

def test_bool():
    assert utils.parse_bool("true") is True
    assert utils.parse_bool("True") is True
    assert utils.parse_bool("yes") is True
    assert utils.parse_bool("on") is True
    assert utils.parse_bool("1") is True

    assert utils.parse_bool("false") is False
    assert utils.parse_bool("False") is False
    assert utils.parse_bool("None") is False
    assert utils.parse_bool("no") is False
    assert utils.parse_bool("off") is False
    assert utils.parse_bool("0") is False

    assert utils.parse_bool("2") is True
    assert utils.parse_bool("3") is True

    assert utils.parse_bool(True) is True
    assert utils.parse_bool(1) is True
    assert utils.parse_bool(2) is True
    assert utils.parse_bool(False) is False
    assert utils.parse_bool(0) is False

def test_supported_version():
    assert utils.supported_version("2.0", "2.0.0", None) is True
    assert utils.supported_version("2.0.0", "2.0.0", None) is True
    assert utils.supported_version("2.0.0", "2.0.0", "2.0.1") is True
    assert utils.supported_version("2.0.0", "2.0.0", "2.0.0") is True

    assert utils.supported_version("2.0.1a1", "2.0.0", "2.0.1") is True
    assert utils.supported_version("2.0.1a1", "2.0.1a0", "2.0.1b1") is True
    assert utils.supported_version("2.0.1b1", "2.0.1", None) is False
    assert utils.supported_version("2.0.1b1", "2.0.1a1", None) is True
    assert utils.supported_version("2.0.1b1", "2.0.1a1", "2.0.1") is True

def test_validate_url():
    assert utils.validate_url("http://google.com/") == "http://google.com/"
    assert utils.validate_url("google.com") == "http://google.com"
    assert utils.validate_url("google.com/test") == "http://google.com/test"
    assert utils.validate_url("https://google.com/") == "https://google.com/"
    assert utils.validate_url("ftp://google.com/") is None
    assert utils.validate_url(
        "https://https://google.com/", allow_invalid=True
    ) == "https://google.com/"

def test_validate_hash():
    assert utils.validate_hash("a") is False
    assert utils.validate_hash("a"*32) is True
    assert utils.validate_hash("A") is False
    assert utils.validate_hash("A"*40) is True
    assert utils.validate_hash("A"*31 + "g") is False
    assert utils.validate_hash("A"*127 + "z") is False
    assert utils.validate_hash("A"*128 + "g") is False

    assert utils.validate_hash(hashlib.md5().hexdigest()) is True
    assert utils.validate_hash(hashlib.sha1().hexdigest()) is True
    assert utils.validate_hash(hashlib.sha256().hexdigest()) is True
    assert utils.validate_hash(hashlib.sha512().hexdigest()) is True

    assert utils.validate_hash("http://cuckoosandbox.org/1234567") is False

def test_list_of():
    assert utils.list_of_strings(1) is False
    assert utils.list_of_strings("a") is False
    assert utils.list_of_strings([]) is True
    assert utils.list_of_strings(["a"]) is True
    assert utils.list_of_strings(["a", 1]) is False
    assert utils.list_of_strings(["a", []]) is False
    assert utils.list_of_strings(["a", ["a"]]) is False
    assert utils.list_of_strings([lambda x: x]) is False

    assert utils.list_of_ints(1) is False
    assert utils.list_of_ints("1") is False
    assert utils.list_of_ints(["1"]) is False
    assert utils.list_of_ints([1]) is True
    assert utils.list_of_ints([1, "1"]) is False
    assert utils.list_of_ints([1, 2]) is True
    assert utils.list_of_ints([lambda x: x]) is False

def test_is_whitelisted_domain():
    assert is_whitelisted_domain("java.com") is True
    assert is_whitelisted_domain("java2.com") is False
    assert is_whitelisted_domain("crl.microsoft.com") is True
