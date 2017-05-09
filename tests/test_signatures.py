# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import pytest
import shutil
import struct
import tempfile

from cuckoo.common.abstracts import Signature
from cuckoo.common.objects import Dictionary
from cuckoo.core.database import Database
from cuckoo.core.plugins import RunSignatures, RunProcessing
from cuckoo.core.startup import init_yara, init_modules, HAVE_YARA
from cuckoo.main import cuckoo_create
from cuckoo.misc import cwd, set_cwd, mkdir

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

    assert not rs.should_enable_signature(sig_not_enabled)

    class sig_empty_name(object):
        enabled = True
        name = None

    assert not rs.should_enable_signature(sig_empty_name)

    class sig_enable_false(object):
        enabled = True
        name = "enable_false"
        minimum = "2.0.0"
        maximum = None

        def enable(self):
            return False

    assert not rs.should_enable_signature(sig_enable_false())

    class sig_enable_true(object):
        enabled = True
        name = "enable_true"
        minimum = "2.0.0"
        maximum = None
        platform = None

        def enable(self):
            return True

    assert rs.should_enable_signature(sig_enable_true())

    class sig_empty_platform(object):
        enabled = True
        name = "empty_platform"
        minimum = "2.0.0"
        maximum = None
        platform = None

    assert rs.should_enable_signature(sig_empty_platform())

    class sig_other_platform(object):
        enabled = True
        name = "other_platform"
        minimum = "2.0.0"
        maximum = None
        platform = "nope"

    assert not rs.should_enable_signature(sig_other_platform())

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

def test_check_suricata():
    class caller(object):
        results = {
            "suricata": {
                "alerts": [{
                    "signature": "SID_TEST",
                }],
            },
        }

    s = Signature(caller)
    assert s.check_suricata_alerts(".*TEST.*")

@mock.patch("cuckoo.core.plugins.log")
def test_signature_severity(p):
    class sig(object):
        name = "foobar"
        matched = True
        severity = 42

        def init(self):
            pass

        def on_complete(self):
            pass

        def results(self):
            return self.__class__.__dict__

    rs = RunSignatures({})
    rs.signatures = sig(),
    rs.run()
    assert p.debug.call_count == 2
    assert p.debug.call_args_list[1][1]["extra"] == {
        "action": "signature.match", "status": "success",
        "signature": "foobar", "severity": 42,
    }

@pytest.mark.skipif(not HAVE_YARA, reason="Yara has not been installed")
def test_on_yara():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    init_modules()

    shutil.copy(
        cwd("yara", "binaries", "vmdetect.yar"),
        cwd("yara", "memory", "vmdetect.yar")
    )
    init_yara(True)

    mkdir(cwd(analysis=1))
    open(cwd("binary", analysis=1), "wb").write("\x0f\x3f\x07\x0b")

    mkdir(cwd("files", analysis=1))
    open(cwd("files", "1.txt", analysis=1), "wb").write("\x56\x4d\x58\x68")

    mkdir(cwd("memory", analysis=1))
    open(cwd("memory", "1-0.dmp", analysis=1), "wb").write(
        struct.pack("QIIII", 0x400000, 0x1000, 0, 0, 0) + "\x45\xc7\x00\x01"
    )

    Database().connect()
    results = RunProcessing(task=Dictionary({
        "id": 1,
        "category": "file",
        "target": __file__,
    })).run()
    assert results["target"]["file"]["yara"][0]["offsets"] == {
        "virtualpc": [(0, 0)],
    }
    assert results["procmemory"][0]["yara"][0]["offsets"] == {
        "vmcheckdll": [(24, 0)],
    }
    assert results["dropped"][0]["yara"][0]["offsets"] == {
        "vmware": [(0, 0)],
        "vmware1": [(0, 0)],
    }

    class sig1(object):
        name = "sig1"

        @property
        def matched(self):
            return False

        @matched.setter
        def matched(self, value):
            pass

        def init(self):
            pass

        def on_signature(self):
            pass

        def on_complete(self):
            pass

        on_yara = mock.MagicMock()

    rs = RunSignatures(results)

    rs.signatures = sig1(),
    rs.run()

    assert sig1.on_yara.call_count == 3
    sig1.on_yara.assert_any_call(
        "sample", cwd("binary", analysis=1), mock.ANY
    )
    sig1.on_yara.assert_any_call(
        "dropped", cwd("files", "1.txt", analysis=1), mock.ANY
    )
    sig1.on_yara.assert_any_call(
        "procmem", cwd("memory", "1-0.dmp", analysis=1), mock.ANY
    )
    assert sig1.on_yara.call_args_list[0][0][2]["offsets"] == {
        "virtualpc": [(0, 0)],
    }
