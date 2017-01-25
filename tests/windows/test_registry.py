# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import random
import _winreg

from lib.common.registry import (
    regkey_exists, set_regkey, set_regkey_full, del_regkey, query_value
)

def random_regkey():
    return "Software\\unittest_%s" % random.randint(0, 2**32)

def test_setreg():
    regkey = random_regkey()
    assert not regkey_exists(_winreg.HKEY_CURRENT_USER, regkey)
    assert query_value(_winreg.HKEY_CURRENT_USER, regkey, "foo") is None

    set_regkey(
        _winreg.HKEY_CURRENT_USER, regkey,
        "foo", _winreg.REG_SZ, "bar"
    )

    assert regkey_exists(_winreg.HKEY_CURRENT_USER, regkey)
    assert query_value(_winreg.HKEY_CURRENT_USER, regkey, "foo") == "bar"

def test_setregfull():
    regkey = random_regkey()
    set_regkey_full(
        "HKEY_CURRENT_USER\\%s\\foo" % regkey, _winreg.REG_SZ, "bar2"
    )

    assert regkey_exists(_winreg.HKEY_CURRENT_USER, regkey)
    assert query_value(_winreg.HKEY_CURRENT_USER, regkey, "foo") == "bar2"

def test_delregkey():
    regkey = random_regkey()
    set_regkey_full(
        "HKEY_CURRENT_USER\\%s\\del" % regkey, _winreg.REG_SZ, "delete"
    )
    del_regkey(_winreg.HKEY_CURRENT_USER, "%s\\del" % regkey)
    assert not regkey_exists(_winreg.HKEY_CURRENT_USER, "%s\\del" % regkey)
    assert regkey_exists(_winreg.HKEY_CURRENT_USER, regkey)

    del_regkey(_winreg.HKEY_CURRENT_USER, regkey)
    assert not regkey_exists(_winreg.HKEY_CURRENT_USER, "%s\\del" % regkey)
    assert not regkey_exists(_winreg.HKEY_CURRENT_USER, regkey)

def test_delregtree():
    regkey = random_regkey()
    set_regkey_full(
        "HKEY_CURRENT_USER\\%s\\del" % regkey, _winreg.REG_SZ, "delete"
    )
    del_regkey(_winreg.HKEY_CURRENT_USER, regkey)
    assert not regkey_exists(_winreg.HKEY_CURRENT_USER, "%s\\del" % regkey)
    assert not regkey_exists(_winreg.HKEY_CURRENT_USER, regkey)

def test_dword():
    regkey = random_regkey()
    set_regkey_full(
        "HKEY_CURRENT_USER\\%s\\foo" % regkey, _winreg.REG_DWORD, 1234
    )

    assert regkey_exists(_winreg.HKEY_CURRENT_USER, regkey)
    assert query_value(
        _winreg.HKEY_CURRENT_USER, regkey, "foo"
    ) == 1234

def test_multisz():
    regkey = random_regkey()
    set_regkey_full(
        "HKEY_CURRENT_USER\\%s\\foo" % regkey, _winreg.REG_MULTI_SZ,
        ["a", "b", "c"]
    )

    assert regkey_exists(_winreg.HKEY_CURRENT_USER, regkey)
    assert query_value(
        _winreg.HKEY_CURRENT_USER, regkey, "foo"
    ) == ["a", "b", "c"]
