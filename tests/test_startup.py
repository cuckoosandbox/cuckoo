# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import responses
import tempfile

from cuckoo.core.startup import init_modules, check_version
from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd, load_signatures

@mock.patch("cuckoo.core.startup.log")
def test_init_modules(p):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    load_signatures()

    logs = []

    def log(fmt, *args):
        logs.append(fmt % args if args else fmt)

    p.debug.side_effect = log

    init_modules()

    logs = "\n".join(logs)
    assert "KVM" in logs
    assert "Xen" in logs
    assert "CreatesExe" in logs
    assert "SystemMetrics" in logs

def test_check_version_disabled(capsys):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "cuckoo": {
            "cuckoo": {
                "version_check": False,
            },
        },
    })
    check_version()
    out, err = capsys.readouterr()
    assert "Checking for" not in out

@responses.activate
def test_version_20rc1(capsys):
    set_cwd(tempfile.mkdtemp())
    responses.add(
        responses.POST, "http://api.cuckoosandbox.org/checkversion.php",
        status=200, json={
            "error": False,
            "current": "2.0-rc1",
            "response": "NEW_VERSION",
        }
    )

    check_version()
    out, err = capsys.readouterr()
    assert "Checking for" in out
    assert "You're good to go" in out

@responses.activate
def test_version_newer(capsys):
    set_cwd(tempfile.mkdtemp())
    responses.add(
        responses.POST, "http://api.cuckoosandbox.org/checkversion.php",
        status=200, json={
            "error": False,
            "current": "20.0.0",
            "response": "NEW_VERSION",
        }
    )

    check_version()
    out, err = capsys.readouterr()
    assert "Checking for" in out
    assert "Outdated!" in out
    assert "Cuckoo Sandbox version 20.0.0 is available now" in out

@responses.activate
def test_version_garbage(capsys):
    set_cwd(tempfile.mkdtemp())
    responses.add(
        responses.POST, "http://api.cuckoosandbox.org/checkversion.php",
        status=200, json={
            "error": False,
            "current": "thisisnotaversion",
            "response": "NEW_VERSION",
        }
    )

    check_version()
    out, err = capsys.readouterr()
    assert "Checking for" in out
    assert "Outdated!" in out

    # Just to be sure we emit the garbage as well.
    assert "Cuckoo Sandbox version thisisnotaversion is available now" in out

@responses.activate
def test_version_resp404(capsys):
    set_cwd(tempfile.mkdtemp())
    responses.add(
        responses.POST, "http://api.cuckoosandbox.org/checkversion.php",
        status=404
    )

    check_version()
    out, err = capsys.readouterr()
    assert "Checking for" in out
    assert "Error checking for" in out

@responses.activate
def test_version_respinvld(capsys):
    set_cwd(tempfile.mkdtemp())
    responses.add(
        responses.POST, "http://api.cuckoosandbox.org/checkversion.php",
        status=200, json=["this is not a dictionary"]
    )

    check_version()
    out, err = capsys.readouterr()
    assert "Checking for" in out
    assert "Error checking for" in out
