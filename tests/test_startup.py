# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import pytest
import responses
import socket
import tempfile

from cuckoo.common.exceptions import CuckooStartupError
from cuckoo.core.startup import init_modules, check_version, init_rooter
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

@mock.patch("cuckoo.core.startup.socket")
def test_init_rooter_no(p):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "routing": {
            "routing": {
                "route": "none",
                "internet": "none",
                "drop": False,
            },
            "inetsim": {
                "enabled": False,
            },
            "tor": {
                "enabled": False,
            },
            "vpn": {
                "enabled": False,
            },
        },
    })

    init_rooter()
    p.socket.assert_not_called()

@mock.patch("cuckoo.core.startup.socket")
def test_init_rooter_yes(p):
    options = [
        ("routing", "route", "internet"),
        ("routing", "internet", "eth0"),
        ("routing", "drop", True),
        ("inetsim", "enabled", True),
        ("tor", "enabled", True),
        ("vpn", "enabled", True),
    ]

    # In order to be able to throw the socket.error exception we have to patch
    # it (so that it accepts Exception instances).
    p.error = Exception

    e = Exception()
    e.strerror = "error"
    p.socket.return_value.connect.side_effect = e

    for section, entry, value in options:
        set_cwd(tempfile.mkdtemp())
        cfg = {
            "routing": {
                "routing": {
                    "route": "none",
                    "internet": "none",
                    "drop": False,
                },
                "inetsim": {
                    "enabled": False,
                },
                "tor": {
                    "enabled": False,
                },
                "vpn": {
                    "enabled": False,
                },
            },
        }
        cfg["routing"][section][entry] = value
        cuckoo_create(cfg=cfg)

        with pytest.raises(CuckooStartupError):
            init_rooter()
        p.socket.assert_called_once()
        p.socket.reset_mock()

@mock.patch("cuckoo.core.startup.rooter")
@mock.patch("cuckoo.core.startup.socket")
def test_init_rooter_connect(p, q):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "routing": {
            "routing": {
                "internet": "eth0",
            },
        },
    })

    init_rooter()
    p.socket.return_value.connect.assert_called_once_with("/tmp/cuckoo-rooter")
    q.assert_called_once_with("forward_drop")

@mock.patch("cuckoo.core.startup.socket")
def test_init_rooter_exceptions(p):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "routing": {
            "routing": {
                "internet": "eth0",
            },
        },
    })

    p.error = Exception

    e = Exception()
    e.strerror = "No such file or directory"
    p.socket.return_value.connect.side_effect = e
    with pytest.raises(CuckooStartupError) as e:
        init_rooter()
    e.match("different Unix socket path")

    e = Exception()
    e.strerror = "Connection refused"
    p.socket.return_value.connect.side_effect = e
    with pytest.raises(CuckooStartupError) as e:
        init_rooter()
    e.match("rooter is not actually running")

    e = Exception()
    e.strerror = "Permission denied"
    p.socket.return_value.connect.side_effect = e
    with pytest.raises(CuckooStartupError) as e:
        init_rooter()
    e.match("due to incorrect permissions")
