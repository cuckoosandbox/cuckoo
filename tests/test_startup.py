# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import pytest
import tempfile

from cuckoo.common.exceptions import CuckooStartupError
from cuckoo.core.startup import init_modules, init_routing
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
