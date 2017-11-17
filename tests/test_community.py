# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import io
import pytest
import responses
import tarfile
import tempfile

from cuckoo.apps.apps import fetch_community, URL
from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.common.files import Files, Folders
from cuckoo.misc import set_cwd, cwd

@responses.activate
def test_failed_fetch():
    responses.add(responses.GET, URL % "master", status=404)

    with pytest.raises(CuckooOperationalError) as e:
        fetch_community()
    e.match("Error fetching")

@responses.activate
def test_extract():
    o = io.BytesIO()
    t = tarfile.open(fileobj=o, mode="w:gz")

    a = tempfile.mktemp()
    open(a, "wb").write("a")
    t.add(a, "community-master/modules/signatures/a.txt")

    b = tempfile.mktemp()
    open(b, "wb").write("b")
    t.add(b, "community-master/data/monitor/b.txt")

    y = tempfile.mktemp()
    open(y, "wb").write("y")
    t.add(y, "community-master/data/yara/binaries/y.yar")

    c = tempfile.mktemp()
    open(c, "wb").write("c")
    t.add(c, "community-master/agent/c.txt")

    d = tempfile.mkdtemp()
    Folders.create(d, "dir1")
    Folders.create(d, "dir2")
    Folders.create((d, "dir2"), "dir3")
    Files.create((d, "dir1"), "d.txt", "d")
    Files.create((d, "dir2", "dir3"), "e.txt", "e")
    t.add(d, "community-master/analyzer")

    t.close()

    responses.add(responses.GET, URL % "master", body=o.getvalue())

    set_cwd(tempfile.mkdtemp())
    fetch_community()

    assert open(cwd("signatures", "a.txt"), "rb").read() == "a"
    assert open(cwd("monitor", "b.txt"), "rb").read() == "b"
    assert open(cwd("yara", "binaries", "y.yar"), "rb").read() == "y"
    assert open(cwd("agent", "c.txt"), "rb").read() == "c"
    assert open(cwd("analyzer", "dir1", "d.txt"), "rb").read() == "d"
    assert open(cwd("analyzer", "dir2", "dir3", "e.txt"), "rb").read() == "e"
