# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock

from cuckoo.core.plugins import RunSignatures

def test_signature_version():
    rs = RunSignatures({})

    class sig_normal(object):
        name = "sig_normal"
        minimum = "2.0.0"
        maximum = None

    rs.version = "2.0.0"
    assert rs.check_signature_version(sig_normal)

    rs.version = "2.2.0"
    assert rs.check_signature_version(sig_normal)

    class sig_run(object):
        name = "sig_run"
        minimum = "2.0.0"
        maximum = None

        def run(self):
            pass

    assert not rs.check_signature_version(sig_run)

    class sig_outdated(object):
        name = "sig_outdated"
        minimum = "2.0.3"
        maximum = None

    rs.version = "2.0.0"
    assert not rs.check_signature_version(sig_outdated)

    class sig_obsolete(object):
        name = "sig_obsolete"
        minimum = "2.0.0"
        maximum = "2.0.9"

    rs.version = "2.1.0"
    assert not rs.check_signature_version(sig_obsolete)

def test_should_enable_signature():
    rs = RunSignatures({})
    rs.version = "2.0.0"

    class sig_not_enabled(object):
        enabled = False

    assert not rs._should_enable_signature(sig_not_enabled)

    class sig_empty_name(object):
        enabled = True
        name = None

    assert not rs._should_enable_signature(sig_empty_name)

    class sig_enable_false(object):
        enabled = True
        name = "enable_false"
        minimum = "2.0.0"
        maximum = None

        def enable(self):
            return False

    assert not rs._should_enable_signature(sig_enable_false())

    class sig_enable_true(object):
        enabled = True
        name = "enable_true"
        minimum = "2.0.0"
        maximum = None
        platform = None

        def enable(self):
            return True

    assert rs._should_enable_signature(sig_enable_true())

    class sig_empty_platform(object):
        enabled = True
        name = "empty_platform"
        minimum = "2.0.0"
        maximum = None
        platform = None

    assert rs._should_enable_signature(sig_empty_platform())

    class sig_other_platform(object):
        enabled = True
        name = "other_platform"
        minimum = "2.0.0"
        maximum = None
        platform = "nope"

    assert not rs._should_enable_signature(sig_other_platform())

def test_signature_order():
    class sig(object):
        enabled = True
        minimum = "2.0.0"
        maximum = None
        platform = "windows"

        def __init__(self, caller):
            pass

    class sig1(sig):
        name = "sig1"
        order = 3

    class sig2(sig):
        name = "sig2"
        order = 1

    class sig3(sig):
        name = "sig3"
        order = 2

    with mock.patch("cuckoo.core.plugins.cuckoo") as p:
        p.signatures = sig1, sig2, sig3
        rs = RunSignatures({})

    assert isinstance(rs.signatures[0], sig2)
    assert isinstance(rs.signatures[1], sig3)
    assert isinstance(rs.signatures[2], sig1)

class test_call_signature():
    class sig(object):
        enabled = True
        name = "sig"
        minimum = "2.0.0"
        maximum = None
        platform = "windows"
        matched = False
        order = 1

        def __init__(self, caller):
            pass

        def on_signature(self, sig):
            pass

    with mock.patch("cuckoo.core.plugins.cuckoo") as p:
        p.signatures = sig,
        rs = RunSignatures({})

    s1 = rs.signatures[0]

    # Not a match.
    f = mock.MagicMock(return_value=False)
    s1.matched = False
    rs.call_signature(s1, f, 1, 2, a=3, b=4)
    assert s1.matched is False
    f.assert_called_once_with(1, 2, a=3, b=4)

    # It is a match.
    f = mock.MagicMock(return_value=True)
    rs.call_signature(s1, f, "foo", "bar")
    assert s1.matched is True
    f.assert_called_once_with("foo", "bar")

    # Now it is a match, no longer call the handler.
    f = mock.MagicMock()
    rs.call_signature(s1, f, "foo", "bar")
    f.assert_not_called()
