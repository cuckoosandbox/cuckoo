# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cuckoo.common.netlog import (
    pointer_converter_32bit, pointer_converter_64bit
)

def test_pointer_repr():
    assert pointer_converter_32bit(0) == "0x00000000"
    assert pointer_converter_32bit(1) == "0x00000001"
    assert pointer_converter_32bit(0xffffffff) == "0xffffffff"

    assert pointer_converter_64bit(0) == "0x0000000000000000"
    assert pointer_converter_64bit(1) == "0x0000000000000001"
    assert pointer_converter_64bit(0xffffffff) == "0x00000000ffffffff"
    assert pointer_converter_64bit(0xffffffffffffffff) == "0xffffffffffffffff"
