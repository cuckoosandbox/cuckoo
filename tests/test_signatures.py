# Copyright (C) 2017-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import os.path
import shutil
import struct
import tempfile

from cuckoo.common.abstracts import Signature
from cuckoo.common.objects import Dictionary
from cuckoo.common.scripting import Scripting
from cuckoo.core.database import Database
from cuckoo.core.extract import ExtractManager
from cuckoo.core.plugins import RunSignatures, RunProcessing
from cuckoo.core.startup import init_yara, init_modules
from cuckoo.main import cuckoo_create
from cuckoo.misc import cwd, set_cwd, mkdir

def test_signature_version():
    rs = RunSignatures

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

def test_should_load_signature():
    rs = RunSignatures
    rs.version = "2.0.0"

    class sig_not_enabled(object):
        enabled = False

    assert not rs.should_load_signature(sig_not_enabled)

    class sig_empty_name(object):
        enabled = True
        name = None

    assert not rs.should_load_signature(sig_empty_name)

    class sig_enable_false(object):
        enabled = True
        name = "enable_false"
        minimum = "2.0.0"
        maximum = None

        def enable(self):
            return False

    assert not rs.should_load_signature(sig_enable_false())

    class sig_enable_true(object):
        enabled = True
        name = "enable_true"
        minimum = "2.0.0"
        maximum = None
        platform = None

        def enable(self):
            return True

    assert rs.should_load_signature(sig_enable_true())

def test_should_enable_signature_empty_platform():
    rs = RunSignatures({})

    class sig_empty_platform(object):
        platform = None

    assert rs.should_enable_signature(sig_empty_platform())

    class sig_other_platform(object):
        platform = "nope"

    assert not rs.should_enable_signature(sig_other_platform())

    class sig_windows_platform(object):
        platform = "windows"

    assert rs.should_enable_signature(sig_windows_platform())

def test_should_enable_signature_linux_platform():
    rs = RunSignatures({
        "info": {
            "platform": "linux",
        },
    })

    class sig_empty_platform(object):
        platform = None

    assert rs.should_enable_signature(sig_empty_platform())

    class sig_other_platform(object):
        platform = "nope"

    assert not rs.should_enable_signature(sig_other_platform())

    class sig_windows_platform(object):
        platform = "windows"

    assert not rs.should_enable_signature(sig_windows_platform())

def test_should_enable_signature_windows_platform():
    rs = RunSignatures({
        "info": {
            "platform": "windows",
        },
    })

    class sig_empty_platform(object):
        platform = None

    assert rs.should_enable_signature(sig_empty_platform())

    class sig_other_platform(object):
        platform = "nope"

    assert not rs.should_enable_signature(sig_other_platform())

    class sig_windows_platform(object):
        platform = "windows"

    assert rs.should_enable_signature(sig_windows_platform())

def test_signature_order():
    class sig(Signature):
        enabled = True
        minimum = "2.0.0"
        maximum = None
        platform = "windows"
        marks = []

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

    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    with mock.patch("cuckoo.core.plugins.cuckoo") as p:
        p.signatures = sig1, sig2, sig3
        RunSignatures.init_once()
        rs = RunSignatures({})

    assert isinstance(rs.signatures[0], sig2)
    assert isinstance(rs.signatures[1], sig3)
    assert isinstance(rs.signatures[2], sig1)

class test_call_signature():
    class sig(Signature):
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

    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    with mock.patch("cuckoo.core.plugins.cuckoo") as p:
        p.signatures = sig,
        RunSignatures.init_once()
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
        marks = []

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

def test_mark_config():
    class sig(Signature):
        name = "foobar"

        def on_complete(self):
            self.mark_config({
                "family": "foobar",
                "cnc": "thisiscnc.com",
                "url": [
                    "url1", "url2",
                ],
            })
            return True

    rs = RunSignatures({
        "metadata": {},
    })
    rs.signatures = sig(rs), sig(rs)
    rs.run()
    assert rs.results["metadata"] == {
        "cfgextr": [{
            "family": "foobar",
            "cnc": [
                "thisiscnc.com",
            ],
            "url": [
                "url1", "url2",
            ],
        }],
    }

def test_on_yara():
    set_cwd(os.path.realpath(tempfile.mkdtemp()))
    cuckoo_create()
    init_modules()

    shutil.copy(
        cwd("yara", "binaries", "vmdetect.yar"),
        cwd("yara", "memory", "vmdetect.yar")
    )
    init_yara()

    mkdir(cwd(analysis=1))
    open(cwd("binary", analysis=1), "wb").write("\x0f\x3f\x07\x0b")

    mkdir(cwd("files", analysis=1))
    open(cwd("files", "1.txt", analysis=1), "wb").write("\x56\x4d\x58\x68")

    mkdir(cwd("memory", analysis=1))
    open(cwd("memory", "1-0.dmp", analysis=1), "wb").write(
        struct.pack("QIIII", 0x400000, 0x1000, 0, 0, 0) + "\x45\xc7\x00\x01"
    )

    Database().connect()
    ExtractManager._instances = {}
    results = RunProcessing(task=Dictionary({
        "id": 1,
        "category": "file",
        "target": __file__,
    })).run()
    assert results["target"]["file"]["yara"][0]["offsets"] == {
        "virtualpc": [(0, 0)],
    }
    assert results["procmemory"][0]["regions"] == [{
        "addr": "0x00400000",
        "end": "0x00401000",
        "offset": 24,
        "protect": None,
        "size": 4096,
        "state": 0,
        "type": 0,
    }]
    assert results["procmemory"][0]["yara"][0]["offsets"] == {
        "vmcheckdll": [(24, 0)],
    }
    assert results["dropped"][0]["yara"][0]["offsets"] == {
        "vmware": [(0, 0)],
        "vmware1": [(0, 0)],
    }

    class sig1(Signature):
        name = "sig1"

        @property
        def matched(self):
            return False

        @matched.setter
        def matched(self, value):
            pass

        def init(self):
            pass

        def on_signature(self, sig):
            pass

        def on_complete(self):
            pass

        def on_extract(self, match):
            pass

        on_yara = mock.MagicMock()

    rs = RunSignatures(results)

    rs.signatures = sig1(rs),
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
    ym = sig1.on_yara.call_args_list[0][0][2]
    assert ym.offsets == {
        "virtualpc": [(0, 0)],
    }
    assert ym.string("virtualpc", 0) == "\x0f\x3f\x07\x0b"

def test_on_extract():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    init_modules()

    Database().connect()
    mkdir(cwd(analysis=2))

    cmd = Scripting().parse_command("cmd.exe /c ping 1.2.3.4")

    ex = ExtractManager.for_task(2)
    ex.push_script({
        "pid": 1,
        "first_seen": 2,
    }, cmd)

    results = RunProcessing(task=Dictionary({
        "id": 2,
        "category": "file",
        "target": __file__,
    })).run()

    assert results["extracted"] == [{
        "category": "script",
        "pid": 1,
        "first_seen": 2,
        "program": "cmd",
        "raw": cwd("extracted", "0.bat", analysis=2),
        "yara": [],
        "info": {},
    }]

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

        def on_yara(self):
            pass

        on_extract = mock.MagicMock()

    rs = RunSignatures(results)

    rs.signatures = sig1(),
    rs.run()

    sig1.on_extract.assert_called_once()
    em = sig1.on_extract.call_args_list[0][0][0]
    assert em.category == "script"

class TestSignatureMethods(object):
    def report(self, obj):
        class caller(object):
            results = obj

        return Signature(caller())

    def test_check_command_line(self):
        r = self.report({
            "behavior": {
                "summary": {
                    "command_line": [
                        "foo", "bar", "foobar",
                    ],
                },
            },
        })
        r.check_command_line("foo") == "foo"
        r.check_command_line("ar$", regex=True) == "bar"

def classes(objects):
    return [s.__class__ for s in objects]

def lazy_compare(unsorted, sorted_lst):
    items = sorted(unsorted, key=lambda v: repr(v))
    assert items == sorted_lst

class TestRunSignatures(object):
    _fake_results = {
        "behavior": {
            "processes": [{
                "process_path": "C:\\Temp\\malware.exe",
                "pid": 123,
                "calls": [
                    {"category": "system", "api": "LdrLoadDll"},
                    {"category": "registry", "api": "GetSystemTimeAsFileTime"},
                    {"category": "xundefined", "api": "XUndefined"}
                ]
            }]
        }
    }

    def _runner(self, signatures):
        class TestRunSignatures(RunSignatures):
            available_signatures = signatures
        return TestRunSignatures(self._fake_results)

    def test_yield_calls(self):
        pass

    def test_dispatch_building(self):
        class SignatureAll(Signature):
            def on_call(self, call, proc):
                pass
        class SignatureDispatch(Signature):
            def on_call_LdrLoadDll(self, call, proc):
                pass
        class SignatureAPI(Signature):
            filter_apinames = ["GetSystemTimeAsFileTime"]
            def on_call(self, call, proc):
                pass
        class SignatureCategory(Signature):
            filter_categories = ["system"]
            def on_call(self, call, proc):
                pass
        class SignatureDummy(Signature):
            pass

        r = self._runner([SignatureAPI, SignatureAll, SignatureCategory,
            SignatureDispatch, SignatureDummy])
        assert len(r.signatures) == 5
        lazy_compare(
            r.call_for_api.keys(),
            ["GetSystemTimeAsFileTime", "LdrLoadDll"]
        )
        assert classes(r.call_for_api["LdrLoadDll"]) == [SignatureDispatch]
        assert classes(r.call_for_cat["system"]) == [SignatureCategory]
        assert SignatureDummy not in classes(r.call_always)
        for v in r.call_for_api.values():
            assert SignatureDummy not in classes(v)
        for v in r.call_for_cat.values():
            assert SignatureDummy not in classes(v)
        assert not r.api_sigs
        r.run()
        lazy_compare(
            r.api_sigs.keys(),
            ["GetSystemTimeAsFileTime", "LdrLoadDll", "XUndefined"]
        )
        lazy_compare(
            classes(r.api_sigs["GetSystemTimeAsFileTime"]),
            [SignatureAPI, SignatureAll]
        )
        lazy_compare(
            classes(r.api_sigs["LdrLoadDll"]),
            [SignatureAll, SignatureCategory, SignatureDispatch]
        )
