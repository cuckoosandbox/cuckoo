# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import tempfile

from cuckoo.common.abstracts import Extractor
from cuckoo.common.scripting import Scripting
from cuckoo.common.shellcode import shikata
from cuckoo.core.extract import ExtractManager
from cuckoo.main import cuckoo_create
from cuckoo.misc import cwd, set_cwd, mkdir
from cuckoo.core.startup import init_yara

def test_basics():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    mkdir(cwd(analysis=1))

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

@mock.patch("cuckoo.core.extract.Extractor.__subclasses__")
def test_ident_shellcode(p):
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

    p.return_value = Shellcode1,

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
