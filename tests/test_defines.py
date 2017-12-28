# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cuckoo.common.defines import (
    REG_NONE, REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD_LITTLE_ENDIAN,
    REG_DWORD, REG_DWORD_BIG_ENDIAN, WIN_PROCESS_QUERY_INFORMATION,
    WIN_ERR_STILL_ALIVE
)

def test_defines():
    assert REG_NONE == 0
    assert REG_SZ == 1
    assert REG_EXPAND_SZ == 2
    assert REG_BINARY == 3
    assert REG_DWORD_LITTLE_ENDIAN == 4
    assert REG_DWORD == 4
    assert REG_DWORD_BIG_ENDIAN == 5
    assert WIN_PROCESS_QUERY_INFORMATION == 0x0400
    assert WIN_ERR_STILL_ALIVE == 259
