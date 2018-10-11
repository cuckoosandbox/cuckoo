# Copyright (C) 2016-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ctypes
import mock
import os
import pytest
import subprocess
import sys
import tempfile
import time

from cuckoo.common.exceptions import CuckooStartupError
from cuckoo.common.files import Files
from cuckoo.common.structures import Structure
from cuckoo.main import cuckoo_create
from cuckoo.misc import (
    dispatch, cwd, set_cwd, getuser, mkdir, Popen, drop_privileges, make_list,
    HAVE_PWD, is_linux, is_windows, is_macosx, decide_cwd, Pidfile,
    format_command
)

def return_value(value):
    return value

def sleep2(value):
    time.sleep(2)
    return value

def test_dispatch():
    assert dispatch(return_value, (1,)) == 1
    assert dispatch(return_value, ("foo",)) == "foo"

    assert dispatch(sleep2, (2,)) == 2
    assert dispatch(sleep2, (2,), timeout=1) is None

    with pytest.raises(RuntimeError):
        dispatch(None, args=None)

    with pytest.raises(RuntimeError):
        dispatch(None, kwargs=None)

    with pytest.raises(RuntimeError):
        dispatch(None, process=False)

def test_cwd():
    set_cwd("/tmp/foo")
    assert cwd() == "/tmp/foo"
    assert cwd("a") == os.path.join("/tmp/foo", "a")
    assert cwd("a", "b") == os.path.join("/tmp/foo", "a", "b")

    set_cwd("/home/user/.cuckoo", "~/.cuckoo")
    assert cwd(raw=True) == "~/.cuckoo"
    assert cwd(root=True) == "/home/user/.cuckoo"
    assert cwd("dump.pcap", analysis=1234) == os.path.join(
        "/home/user/.cuckoo", "storage", "analyses", "1234", "dump.pcap"
    )

    assert os.path.exists(cwd("guids.txt", private=True))

    with pytest.raises(RuntimeError):
        cwd("foo", private=False)

    with pytest.raises(RuntimeError):
        cwd("foo", raw=False)

    with pytest.raises(RuntimeError):
        cwd("foo", root=False)

    with pytest.raises(RuntimeError):
        cwd("foo", analysis=None)

@pytest.mark.skipif(not HAVE_PWD, reason="This test is not for Windows")
def test_getuser():
    # TODO This probably doesn't work on all platforms.
    assert getuser() == subprocess.check_output(["id", "-un"]).strip()

def test_mkdir():
    dirpath = tempfile.mkdtemp()
    assert os.path.isdir(dirpath)
    mkdir(dirpath)
    assert os.path.isdir(dirpath)

    dirpath = tempfile.mktemp()
    assert not os.path.exists(dirpath)
    mkdir(dirpath)
    assert os.path.isdir(dirpath)

@pytest.mark.skipif("sys.platform != 'win32'")
def test_is_windows():
    assert is_windows() is True
    assert is_linux() is False
    assert is_macosx() is False

@pytest.mark.skipif("sys.platform != 'darwin'")
def test_is_macosx():
    assert is_windows() is False
    assert is_linux() is False
    assert is_macosx() is True

@pytest.mark.skipif("sys.platform != 'linux2'")
def test_is_linux():
    assert is_windows() is False
    assert is_linux() is True
    assert is_macosx() is False

def test_platforms():
    """Ensure that the above unit tests are complete (for our supported
    platforms)."""
    assert sys.platform in ("win32", "linux2", "darwin")

def test_popen():
    """Ensures that Popen is working properly."""
    with mock.patch("subprocess.Popen") as p:
        p.return_value = None
        Popen(["foo", "bar"])

    p.assert_called_once_with(["foo", "bar"])

    with mock.patch("subprocess.Popen") as p:
        p.return_value = None
        Popen(
            ["foo", "bar"], close_fds=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

    if is_windows():
        p.assert_called_once_with(
            ["foo", "bar"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
    else:
        p.assert_called_once_with(
            ["foo", "bar"], close_fds=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

    # Test that the method actually works.
    p = Popen("echo 123", stdout=subprocess.PIPE, shell=True)
    out, err = p.communicate()
    assert out.strip() == "123" and not err

    # The following would normally throw an exception on Windows.
    p = Popen("echo 1234", close_fds=True, stdout=subprocess.PIPE, shell=True)
    out, err = p.communicate()
    assert out.strip() == "1234" and not err

def test_decide_cwd():
    orig_cuckoo_cwd = os.environ.pop("CUCKOO_CWD", None)
    orig_cuckoo = os.environ.pop("CUCKOO", None)

    dirpath1 = tempfile.mkdtemp()
    dirpath2 = tempfile.mkdtemp()
    dirpath3 = tempfile.mkdtemp()

    assert decide_cwd(dirpath1) == dirpath1

    assert decide_cwd() == os.path.abspath(os.path.expanduser("~/.cuckoo"))

    curdir = os.getcwd()
    os.chdir(dirpath2)
    open(".cwd", "wb").write("A"*40)

    assert decide_cwd() == os.path.abspath(".")
    os.chdir(curdir)

    os.environ["CUCKOO"] = dirpath2
    assert decide_cwd(dirpath1) == dirpath1
    assert decide_cwd() == dirpath2

    os.environ["CUCKOO_CWD"] = dirpath3
    assert decide_cwd(dirpath1) == dirpath1
    assert decide_cwd() == dirpath3

    with pytest.raises(CuckooStartupError) as e:
        decide_cwd(tempfile.mktemp(), exists=True)
    e.match("is not present")

    with pytest.raises(CuckooStartupError) as e:
        decide_cwd(dirpath1, exists=True)
    e.match("is not a proper CWD")

    Files.create(dirpath1, ".cwd", "A"*40)
    assert decide_cwd(dirpath1, exists=True) == dirpath1

    # Cleanup.
    if orig_cuckoo:
        os.environ["CUCKOO"] = orig_cuckoo
    else:
        os.environ.pop("CUCKOO", None)

    if orig_cuckoo_cwd:
        os.environ["CUCKOO_CWD"] = orig_cuckoo_cwd
    else:
        os.environ.pop("CUCKOO_CWD", None)

@pytest.mark.skipif("sys.platform != 'linux2'")
@mock.patch("cuckoo.misc.pwd")
@mock.patch("cuckoo.misc.os")
def test_drop_privileges(p, q):
    drop_privileges("username")
    q.getpwnam.assert_called_once_with("username")
    p.setgroups.assert_called_once()
    p.setgid.assert_called_once()
    p.setuid.assert_called_once()
    p.putenv.assert_called_once()

def test_structure():
    class S1(Structure):
        _pack_ = 1
        _fields_ = [
            ("a", ctypes.c_ubyte),
            ("b", ctypes.c_ushort),
            ("c", ctypes.c_uint),
            ("d", ctypes.c_ubyte * 128),
        ]

    class S2(Structure):
        _pack_ = 1
        _fields_ = [
            ("a", S1),
            ("b", ctypes.c_ulonglong),
            ("c", ctypes.c_char * 32),
        ]

    a = S2.from_buffer_copy("A"*175)
    assert a.a.a == 0x41
    assert a.a.b == 0x4141
    assert a.a.c == 0x41414141
    assert a.a.d[:] == [0x41] * 128
    assert a.b == 0x4141414141414141
    assert a.c == "A"*32
    assert a.as_dict() == {
        "a": {
            "a": 0x41,
            "b": 0x4141,
            "c": 0x41414141,
            "d": [0x41] * 128,
        },
        "b": 0x4141414141414141,
        "c": "A"*32,
    }

def test_create_pidfile():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    Pidfile("test1").create()
    assert int(open(cwd("pidfiles", "test1.pid"), "rb").read()) == os.getpid()

def test_remove_pidfile():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    Pidfile("test2").create()
    assert os.path.exists(cwd("pidfiles", "test2.pid"))

    Pidfile("test2").remove()
    assert not os.path.exists(cwd("pidfiles", "test2.pid"))

def test_pidfile_exists_false():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    assert not Pidfile("test3").exists()

def test_pidfile_exists_true():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    p = Pidfile("test4")
    p.create()
    assert p.exists() and p.pid == os.getpid()

def test_pidfile_none():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    p = Pidfile("test5")
    p.create()

    open(cwd("pidfiles", "test5.pid"), "wb").write("notapid")
    assert p.read() is None

def test_proc_exists():
    assert Pidfile("hello").proc_exists(os.getpid())
    # Chances are possible, but slim.
    assert not Pidfile("hello").proc_exists(13337)

    assert not Pidfile("hello)").proc_exists(None)
    assert not Pidfile("hello)").proc_exists("")

@mock.patch("cuckoo.misc.sys")
def test_pid_exists_unsupported_platform(p):
    p.platform = "DogeOS"
    assert Pidfile("hello").proc_exists(os.getpid()) is None

def test_active_pids():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    Pidfile("test6").create()
    assert Pidfile.get_active_pids() == {
        "test6": os.getpid(),
    }

def test_make_list():
    assert make_list("hello") == ["hello"]
    assert make_list(1) == [1]
    assert make_list((1, 2)) == [1, 2]
    assert make_list([3, 4]) == [3, 4]

def test_format_command():
    set_cwd(tempfile.mkdtemp(), ".")
    assert format_command("community") == "cuckoo community"

    set_cwd(tempfile.mkdtemp(), "~/.cuckoo")
    assert format_command("community") == "cuckoo community"

    dirpath = tempfile.mkdtemp()
    set_cwd(dirpath, dirpath)
    assert format_command("community") == "cuckoo --cwd %s community" % cwd()

    dirpath = tempfile.mkdtemp("foo bar")
    set_cwd(dirpath, dirpath)
    assert format_command("community") == 'cuckoo --cwd "%s" community' % cwd()

    dirpath = tempfile.mkdtemp("foo ' bar")
    set_cwd(dirpath, dirpath)
    assert format_command("community") == 'cuckoo --cwd "%s" community' % cwd()
