# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cuckoo.common.defines import PUBLICKEYSTRUC, RSAPUBKEY, REG_DWORD

def test_defines():
    a = PUBLICKEYSTRUC.from_buffer_copy("A"*8)
    assert a.type == 0x41
    assert a.version == 0x41
    assert a.reserved == 0x4141
    assert a.algid == 0x41414141

    a = RSAPUBKEY.from_buffer_copy("A"*12)
    assert a.magic == 0x41414141
    assert a.bitlen == 0x41414141
    assert a.pubexp == 0x41414141

    assert REG_DWORD == 4
