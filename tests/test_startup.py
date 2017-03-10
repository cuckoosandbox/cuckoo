# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import pytest
import responses
import tempfile

from cuckoo.common.abstracts import (
    Auxiliary, Machinery, Processing, Signature, Report
)
from cuckoo.common.exceptions import CuckooStartupError
from cuckoo.core.startup import (
    init_modules, check_version, init_rooter, init_routing
)
from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd, load_signatures

@mock.patch("cuckoo.reporting.elasticsearch.elastic")
@mock.patch("cuckoo.reporting.mongodb.mongo")
@mock.patch("cuckoo.core.startup.log")
def test_init_modules(p, q, r):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    load_signatures()

    logs = []

    def log(fmt, *args):
        logs.append(fmt % args if args else fmt)

    p.debug.side_effect = log
    r.index_time_pattern = "yearly"

    init_modules()

    logs = "\n".join(logs)
    assert "KVM" in logs
    assert "Xen" in logs
    assert "CreatesExe" in logs
    assert "SystemMetrics" in logs

@mock.patch("cuckoo.core.startup.cuckoo")
def test_modules_init_once(p):
    class A(Auxiliary):
        pass

    class B(Machinery):
        pass

    class C(Processing):
        pass

    class D(Signature):
        pass

    class E(Report):
        pass

    l = []
    for x in xrange(5):
        l.append(mock.MagicMock(__name__="name"))

    a, b, c, d, e = l

    p.plugins = {
        "auxiliary": [A, a],
        "machinery": [B, b],
        "processing": [C, c],
        "signatures": [D, d],
        "reporting": [E, e],
    }

    init_modules()

    a.init_once.assert_called_once()
    b.init_once.assert_called_once()
    c.init_once.assert_called_once()
    d.init_once.assert_called_once()
    e.init_once.assert_called_once()

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

@responses.activate
def test_version_respnotjson(capsys):
    set_cwd(tempfile.mkdtemp())
    responses.add(
        responses.POST, "http://api.cuckoosandbox.org/checkversion.php",
        status=200, body="thisisnotevenjson"
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
    assert q.call_count == 3
    q.assert_any_call("forward_drop")
    q.assert_any_call("state_disable")
    q.assert_any_call("state_enable")

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

@mock.patch("cuckoo.core.startup.rooter")
def test_init_routing_default(p):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    init_routing()
    p.assert_not_called()

@mock.patch("cuckoo.core.startup.rooter")
def test_init_routing_unknown(p):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "routing": {
            "routing": {
                "route": "notaroute",
            },
        },
    })

    with pytest.raises(CuckooStartupError) as e:
        init_routing()
    e.match("is it supposed to be a VPN")

"""TODO Enable when merging the Config changes.
@mock.patch("cuckoo.core.startup.rooter")
def test_init_routing_vpndisabled(p):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "routing": {
            "routing": {
                "route": "thisisvpn",
            },
            "vpn": {
                "vpns": [
                    "thisisvpn",
                ],
            },
            "thisisvpn": {
                "name": "vpn1",
                "description": "this is vpn",
            },
        },
    })

    with pytest.raises(CuckooStartupError) as e:
        init_routing()
    e.match("VPNs have not been enabled")
"""

@mock.patch("cuckoo.core.startup.rooter")
def test_init_routing_internet_exc(p):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "routing": {
            "routing": {
                "internet": "eth0",
            },
        },
    })

    def nic_notavail(cmd, arg):
        return False

    def rt_notavail(cmd, arg):
        if cmd == "rt_available":
            return False
        return True

    p.side_effect = nic_notavail
    with pytest.raises(CuckooStartupError) as e:
        init_routing()
    p.assert_called_once()
    e.match("configured as dirty line is not")

    p.side_effect = rt_notavail
    with pytest.raises(CuckooStartupError) as e:
        init_routing()
    e.match("routing table that has been")

@mock.patch("cuckoo.core.startup.rooter")
def test_init_routing_internet_normal(p):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "routing": {
            "routing": {
                "internet": "eth0",
                "rt_table": "table",
            },
        },
    })

    p.side_effect = True, True, None, None, None, None
    init_routing()
    assert p.call_count == 6
    p.assert_any_call("nic_available", "eth0")
    p.assert_any_call("rt_available", "table")
    p.assert_any_call("disable_nat", "eth0")
    p.assert_any_call("enable_nat", "eth0")
    p.assert_any_call("flush_rttable", "table")
    p.assert_any_call("init_rttable", "table", "eth0")

@mock.patch("cuckoo.core.startup.rooter")
def test_init_routing_tor_inetsim_noint(p):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "routing": {
            "tor": {
                "enabled": True,
            },
            "inetsim": {
                "enabled": True,
            },
        },
    })

    init_routing()
    p.assert_not_called()
