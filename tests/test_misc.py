# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path
import pytest
import subprocess
import tempfile
import time

from cuckoo.misc import dispatch, cwd, set_cwd, getuser, mkdir, HAVE_PWD

def test_dispatch():
    def return_value(value):
        return value

    assert dispatch(return_value, (1,)) == 1
    assert dispatch(return_value, ("foo",)) == "foo"

    def sleep2(value):
        time.sleep(2)
        return value

    assert dispatch(sleep2, (2,)) == 2
    assert dispatch(sleep2, (2,), timeout=1) is None

    with pytest.raises(RuntimeError):
        dispatch(None, args=None)

    with pytest.raises(RuntimeError):
        dispatch(None, kwargs=None)

    with pytest.raises(RuntimeError):
        dispatch(None, process=False)

def test_cwd():
    set_cwd(None)
    assert cwd() is None

    set_cwd("/tmp/foo")
    assert cwd() == "/tmp/foo"
    assert cwd("a") == "/tmp/foo/a"
    assert cwd("a", "b") == "/tmp/foo/a/b"

    set_cwd("/home/user/.cuckoo", "~/.cuckoo")
    assert cwd(raw=True) == "~/.cuckoo"

    assert os.path.exists(cwd("guids.txt", private=True))

@pytest.mark.skipif("not HAVE_PWD")
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
