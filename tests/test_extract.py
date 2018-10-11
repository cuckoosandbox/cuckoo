# Copyright (C) 2017-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import tempfile

from cuckoo.common.abstracts import Extractor
from cuckoo.common.objects import YaraMatch
from cuckoo.common.scripting import Scripting
from cuckoo.common.shellcode import shikata
from cuckoo.core.extract import ExtractManager
from cuckoo.core.plugins import RunSignatures
from cuckoo.core.startup import init_yara
from cuckoo.main import cuckoo_create
from cuckoo.misc import cwd, set_cwd, mkdir
from cuckoo.processing.static import Static

def test_basics():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    mkdir(cwd(analysis=1))
    init_yara()

    em = ExtractManager(1)
    em.write_extracted("foo", "bar")
    filepath = cwd("extracted", "0.foo", analysis=1)
    assert open(filepath, "rb").read() == "bar"

    scr = Scripting()
    cmd = scr.parse_command(
        "powershell -e %s" % "foobar".encode("utf-16le").encode("base64")
    )

    em.push_script({
        "pid": 1,
        "first_seen": 2,
    }, cmd)
    filepath = cwd("extracted", "0.ps1", analysis=1)
    assert open(filepath, "rb").read() == "foobar"

    em.push_command_line(
        "powershell -e %s" % "world!".encode("utf-16le").encode("base64")
    )
    filepath = cwd("extracted", "1.ps1", analysis=1)
    assert open(filepath, "rb").read() == "world!"

def test_push_script_recursive():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    mkdir(cwd(analysis=1))

    open(cwd("yara", "office", "ole.yar"), "wb").write("""
        rule OleInside {
            strings:
                $s1 = "Win32_Process"
            condition:
                filename matches /word\/vbaProject.bin/ and $s1
        }
    """)
    init_yara()

    s = Static()
    s.file_path = "tests/files/createproc1.docm"
    s.set_task({
        "id": 1,
        "category": "file",
        "target": s.file_path,
        "package": "doc",
    })
    s.run()

    assert ExtractManager.for_task(1).results()[0]["yara"] == [{
        "name": "OleInside",
        "meta": {
            "description": "(no description)",
        },
        "offsets": {
            "s1": [
                (3933, 0),
            ],
        },
        "strings": [
            "Win32_Process".encode("base64").strip(),
        ],
    }]

def test_ident_shellcode():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    mkdir(cwd("yara", "scripts"))
    open(cwd("yara", "scripts", "1.yar"), "wb").write("""
rule Shellcode1 {
  strings:
       $Shellcode = /=\s*((0x)?[0-9A-F]{2}\s*[,;]\s*)+/ nocase
  condition:
       all of them
}
""")
    init_yara()

    class Shellcode1(Extractor):
        yara_rules = "Shellcode1"

        def handle_yara(self, filepath, match):
            sc = match.string("Shellcode", 0)
            self.push_shellcode(
                "".join(chr(int(x, 16)) for x in sc[2:-1].split(","))
            )

    ExtractManager.init_once()

    sc = shikata(open("tests/files/shellcode/shikata/1.bin", "rb").read())
    sc = ",".join("0x%02x" % ord(ch) for ch in sc)

    scr = Scripting()
    ps1 = ("[Byte[]]$s = %s;" % sc).encode("utf-16le")
    cmd = scr.parse_command(
        "powershell -e %s" % ps1.encode("base64").replace("\n", "")
    )

    mkdir(cwd(analysis=1))
    em = ExtractManager(1)
    em.push_script({
        "pid": 1,
        "first_seen": 2,
    }, cmd)

    assert len(em.items) == 2
    filepath = cwd("extracted", "0.ps1", analysis=1)
    assert open(filepath, "rb").read().startswith("[Byte[]]$s = 0xfc")

    buf = open(cwd("extracted", "1.bin.txt", analysis=1), "rb").read()
    assert "call 0x88" in buf
    assert "0x00c1: push 0xc69f8957" in buf
    assert ".db 'www.service.chrome-up.date',0" in buf

def test_cfgextr():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    class Trigger1(Extractor):
        yara_rules = "Trigger1"

        def handle_yara(self, filepath, match):
            self.push_config({
                "family": "barfoo",
                "version": "baz",
            })

    ExtractManager.init_once()

    mkdir(cwd(analysis=1))
    em = ExtractManager(1)
    em.handle_yara(None, YaraMatch({
        "name": "Trigger1",
        "meta": None,
        "offsets": None,
        "strings": [],
    }))

    assert len(em.items) == 1

    results = {
        "extracted": em.results(),
        "metadata": {},
        "info": {},
    }
    RunSignatures(results).run()
    assert results == {
        "info": {
            "score": 10.0,
        },
        "metadata": {
            "cfgextr": [{
                "family": "barfoo",
                "version": "baz",
            }],
        },
        "extracted": mock.ANY,
        "signatures": [],
    }
