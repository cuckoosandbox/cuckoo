# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cuckoo.common.structures import (
    PUBLICKEYSTRUC, RSAPUBKEY, LnkEntry, LnkHeader
)

def test_publickeystruct():
    a = PUBLICKEYSTRUC.from_buffer_copy("A"*8)
    assert a.type == 0x41
    assert a.version == 0x41
    assert a.reserved == 0x4141
    assert a.algid == 0x41414141

def test_rsapublickeystruct():
    a = RSAPUBKEY.from_buffer_copy("A"*12)
    assert a.magic == 0x41414141
    assert a.bitlen == 0x41414141
    assert a.pubexp == 0x41414141

def test_lnkentry():
    a = LnkEntry.from_buffer_copy("A"*28)

    assert a.length == 0x41414141
    assert a.first_offset == 0x41414141
    assert a.volume_flags == 0x41414141
    assert a.local_volume == 0x41414141
    assert a.base_path == 0x41414141
    assert a.net_volume == 0x41414141
    assert a.path_remainder == 0x41414141

def test_lnkheader():
    a = LnkHeader.from_buffer_copy("A"*72)

    assert a.signature[:] == [0x41, 0x41, 0x41, 0x41]
    assert a.guid[:] == [0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                         0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41]
    assert a.flags == 0x41414141
    assert a.attrs == 0x41414141
    assert a.creation == 0x4141414141414141
    assert a.access == 0x4141414141414141
    assert a.modified == 0x4141414141414141
    assert a.target_len == 0x41414141
    assert a.icon_len == 0x41414141
    assert a.show_window == 0x41414141
    assert a.hotkey == 0x41414141
