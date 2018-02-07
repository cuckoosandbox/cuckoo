# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import pytest
import re
import tempfile

from cuckoo.common.files import Files
from cuckoo.common.objects import (
    Dictionary, File, Archive, Buffer, YaraMatch, URL_REGEX
)
from cuckoo.core.startup import init_yara
from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd, cwd
from cuckoo.processing.static import PortableExecutable

class TestDictionary(object):
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

class TestFile(object):
    def setup(self):
        # File() will invoke cwd(), so any CWD is required.
        set_cwd(tempfile.mkdtemp())

        self.path = tempfile.mkstemp()[1]
        self.file = File(self.path)

    def test_get_name(self):
        assert self.path.split(os.sep)[-1] == self.file.get_name()

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
        assert "empty" in self.file.get_type()

    def test_get_content_type(self):
        assert self.file.get_content_type() in ["inode/x-empty", "application/x-empty"]

    def test_get_all_type(self):
        assert isinstance(self.file.get_all(), dict)

    def test_get_all_keys(self):
        for key in ["name", "size", "crc32", "md5", "sha1", "sha256", "sha512", "ssdeep", "type"]:
            assert key in self.file.get_all()

class TestMagic(object):
    def test_magic1(self):
        f = File("tests/files/foo.txt")
        assert "ASCII text" in f.get_type()
        assert f.get_content_type() == "text/plain"

    def test_magic2(self):
        pe = PortableExecutable(None)
        assert "ASCII text" in pe._get_filetype("hello world")

    def test_magic3(self):
        assert File(__file__).get_type().startswith((
            "Python script", "ASCII ",
        ))
        assert File(__file__).get_content_type() in (
            "text/x-python", "text/plain",
        )

    @pytest.mark.skipif("sys.platform != 'linux2'")
    def test_symlink_magic(self):
        filepath = tempfile.mktemp()
        os.symlink(__file__, filepath)
        assert File(filepath).get_type().startswith("Python script")
        assert File(filepath).get_content_type() == "text/x-python"

def test_regex():
    r = re.findall(URL_REGEX, "foo http://google.com/search bar")
    assert len(r) == 1
    assert "".join(r[0]) == "http://google.com/search"

@pytest.mark.skipif("sys.platform != 'linux2'")
def test_m2crypto():
    pe = PortableExecutable("tests/files/icardres.dll")
    sig0 = pe.run()["signature"][0]
    assert sig0["organization"] == "Microsoft Corporation"
    assert sig0["sha1"] == "9e95c625d81b2ba9c72fd70275c3699613af61e3"

def test_yara_offsets():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    init_yara()

    buf = (
        # The SSEXY payload as per vmdetect.yar
        "66 0F 70 ?? ?? 66 0F DB ?? ?? ?? ?? "
        "?? 66 0F DB ?? ?? ?? ?? ?? 66 0F EF "
        # A VirtualBox MAC address.
        "30 38 2d 30 30 2d 32 37"
    )
    filepath = Files.temp_put(
        "A"*64 + buf.replace("??", "00").replace(" ", "").decode("hex")
    )
    assert File(filepath).get_yara() == [{
        "meta": {
            "description": "Possibly employs anti-virtualization techniques",
            "author": "nex"
        },
        "name": "vmdetect",
        "offsets": {
            "ssexy": [
                (64, 1),
            ],
            "virtualbox_mac_1a": [
                (88, 0),
            ],
        },
        "strings": [
            "MDgtMDAtMjc=",
            "Zg9wAABmD9sAAAAAAGYP2wAAAAAAZg/v",
        ],
    }]

def test_yara_no_description():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    open(cwd("yara", "binaries", "empty.yara"), "wb").write("""
        rule EmptyRule {
            condition:
                1
        }
        rule DescrRule {
            meta:
                description = "this is description"
            condition:
                1
        }
    """)
    init_yara()
    a, b = File(Files.temp_put("hello")).get_yara()
    assert a["name"] == "EmptyRule"
    assert a["meta"] == {
        "description": "(no description)",
    }
    assert b["name"] == "DescrRule"
    assert b["meta"] == {
        "description": "this is description",
    }

def test_yara_externals():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    open(cwd("yara", "office", "external.yara"), "wb").write("""
        rule ExternalRule {
            condition:
                filename matches /document.xml/
        }
    """)
    init_yara()

    assert not File(Files.temp_put("")).get_yara("office")
    assert not File(Files.temp_put("hello")).get_yara("office", {
        "filename": "hello.jpg",
    })
    a, = File(Files.temp_put("hello")).get_yara("office", {
        "filename": "document.xml",
    })
    assert a["name"] == "ExternalRule"

def test_get_urls():
    filepath = Files.temp_put("""
http://google.com
google.com/foobar
thisisnotadomain
https://1.2.3.4:9001/hello
    """)
    assert sorted(File(filepath).get_urls()) == [
        # TODO Why does this not work properly at my own machine?
        "http://google.com",
        "https://1.2.3.4:9001/hello",
    ]

class TestArchive(object):
    def test_get_file(self):
        a = Archive("tests/files/pdf0.zip")
        assert a.get_file("files/pdf0.pdf").get_size() == 680

    def test_not_temporary_file(self):
        f = File("tests/files/pdf0.pdf")
        assert os.path.exists("tests/files/pdf0.pdf")
        del f
        assert os.path.exists("tests/files/pdf0.pdf")

    def test_temporary_file(self):
        a = Archive("tests/files/pdf0.zip")
        f = a.get_file("files/pdf0.pdf")
        filepath = f.file_path
        assert f.get_size() == 680
        assert os.path.exists(filepath)
        del f
        assert not os.path.exists(filepath)

class TestBuffer(object):
    def test_yara_quick(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()
        init_yara()

        buf = (
            # The SSEXY payload as per vmdetect.yar
            "66 0F 70 ?? ?? 66 0F DB ?? ?? ?? ?? "
            "?? 66 0F DB ?? ?? ?? ?? ?? 66 0F EF "
        )
        contents = "A"*64 + buf.replace("??", "00").replace(" ", "").decode("hex")
        assert Buffer(contents).get_yara_quick("binaries") == ["vmdetect"]

class TestPubPrivKeys(object):
    def test_no_keys(self):
        assert File("tests/files/pdf0.pdf").get_keys() == []

    def test_pub_key(self):
        buf = open("tests/files/pdf0.pdf", "rb").read()
        filepath = Files.temp_put((
            buf +
            "-----BEGIN PUBLIC KEY-----\n"
            "HELLOWORLD\n"
            "-----END PUBLIC KEY-----" +
            buf
        ))
        assert File(filepath).get_keys() == [
            "-----BEGIN PUBLIC KEY-----\n"
            "HELLOWORLD\n"
            "-----END PUBLIC KEY-----"
        ]

    def test_private_key(self):
        buf = open("tests/files/pdf0.pdf", "rb").read()
        filepath = Files.temp_put((
            buf +
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "HELLOWORLD\n"
            "-----END RSA PRIVATE KEY-----" +
            buf
        ))
        assert File(filepath).get_keys() == [
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "HELLOWORLD\n"
            "-----END RSA PRIVATE KEY-----"
        ]

class TestYaraMatch(object):
    def test_basics(self):
        ym = YaraMatch({
            "name": "foo",
            "meta": {},
            "offsets": {
                "a": [
                    (1, 0),
                ],
            },
            "strings": [
                "bar".encode("base64"),
            ],
        })
        assert ym.string("a", 0) == "bar"
        assert ym.string("a") == "bar"

    def test_multiple(self):
        ym = YaraMatch({
            "name": "foo",
            "meta": {},
            "offsets": {
                "a": [
                    (1, 0),
                    (2, 2),
                ],
                "b": [
                    (3, 1),
                ],
            },
            "strings": [
                "bar".encode("base64"),
                "baz".encode("base64"),
                "foo".encode("base64"),
            ],
        })
        assert ym.string("a", 0) == "bar"
        assert ym.string("a", 1) == "foo"
        assert ym.string("b", 0) == "baz"
        assert ym.strings("a") == ["bar", "foo"]
        assert ym.strings("b") == ["baz"]
