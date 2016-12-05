# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import mock
import pytest
import tempfile

import cuckoo.apps.rooter as r
from cuckoo.misc import is_linux

def test_nic_available():
    assert r.nic_available("!") is False

    with mock.patch("subprocess.call") as p:
        p.return_value = 1
        assert r.nic_available("notaninterface") is False

    with mock.patch("subprocess.call") as p:
        p.return_value = 0
        assert r.nic_available("aninterface") is True

def test_rt_available():
    with mock.patch("subprocess.call") as p:
        p.return_value = 0
        assert r.rt_available("main") is True

    with mock.patch("subprocess.call") as p:
        p.return_value = 1
        assert r.rt_available("nope") is False

def test_vpn_status():
    output = (
        " * VPN 'a' is not running\n"
        " * VPN 'b' is running\n"
        " * VPN 'c' is running"
    )
    with mock.patch("cuckoo.apps.rooter.run") as p:
        p.return_value = output, ""
        assert r.vpn_status() == {
            "a": False,
            "b": True,
            "c": True,
        }

def test_vpn_enable():
    with mock.patch("cuckoo.apps.rooter.run") as p:
        r.vpn_enable("foobar")
    p.assert_called_once_with(None, "openvpn", "start", "foobar")

def test_vpn_disable():
    with mock.patch("cuckoo.apps.rooter.run") as p:
        r.vpn_disable("foobar")
    p.assert_called_once_with(None, "openvpn", "stop", "foobar")

def test_forward_drop():
    with mock.patch("cuckoo.apps.rooter.run") as p:
        r.forward_drop()
    p.assert_called_once_with(None, "-P", "FORWARD", "DROP")

def test_enable_nat():
    with mock.patch("cuckoo.apps.rooter.run") as p:
        r.enable_nat("foo")
    p.assert_called_once_with(
        None, "-t", "nat", "-A", "POSTROUTING", "-o", "foo", "-j", "MASQUERADE"
    )

def test_disable_nat():
    with mock.patch("cuckoo.apps.rooter.run") as p:
        r.enable_nat("foo")
    p.assert_called_once_with(
        None, "-t", "nat", "-A", "POSTROUTING", "-o", "foo", "-j", "MASQUERADE"
    )

# TODO init_rttable

def test_flush_rttable():
    with mock.patch("cuckoo.apps.rooter.run") as p:
        r.flush_rttable("table")
    p.assert_called_once_with(None, "route", "flush", "table", "table")

    with mock.patch("cuckoo.apps.rooter.run") as p:
        r.flush_rttable("local")
    p.assert_not_called()

def do_cuckoo_rooter():
    with pytest.raises(SystemExit):
        with mock.patch.dict(r.__dict__, {"HAVE_GRP": False}):
            r.cuckoo_rooter(None, None, None, None, None, None)

    with pytest.raises(SystemExit):
        r.cuckoo_rooter(None, None, None, None, None, None)

    with pytest.raises(SystemExit):
        r.cuckoo_rooter(None, None, None, "DOES NOT EXIST", None, None)

    with pytest.raises(SystemExit):
        r.cuckoo_rooter(None, None, "DOES NOT EXIST", __file__, None, None)

    with pytest.raises(SystemExit):
        r.cuckoo_rooter(None, None, __file__, __file__, "DOES NOT EXIST", None)

    with pytest.raises(SystemExit):
        r.cuckoo_rooter(
            None, None, __file__, __file__, __file__, "DOES NOT EXIST"
        )

    os_getuid = mock.patch("os.getuid").start()

    with pytest.raises(SystemExit):
        os_getuid.return_value = 1000
        r.cuckoo_rooter(None, None, __file__, __file__, __file__, __file__)

    os_getuid.return_value = 0

    socket_path = tempfile.mktemp()

    sock = mock.patch("socket.socket").start()
    sock.return_value.bind.return_value = None

    class gr_obj(object):
        gr_name = "test"
        gr_passwd = "x"
        gr_gid = 1000
        gr_mem = []

    gr = mock.patch("grp.getgrnam").start()

    with pytest.raises(SystemExit):
        gr.side_effect = KeyError("foobar")
        r.cuckoo_rooter(
            socket_path , "group", __file__, __file__, __file__, __file__
        )

    gr.side_effect = None
    gr.return_value = gr_obj

    os_chown = mock.patch("os.chown").start()
    os_chown.return_value = None

    os_chmod = mock.patch("os.chmod").start()
    os_chmod.return_value = None

    with pytest.raises(SystemExit):
        sock.return_value.recvfrom.side_effect = SystemExit
        r.cuckoo_rooter(
            socket_path , "group", __file__, __file__, __file__, __file__
        )

    with pytest.raises(SystemExit):
        sock.return_value.recvfrom.side_effect = (
            ("this is not json", None), SystemExit
        )
        r.cuckoo_rooter(
            socket_path , "group", __file__, __file__, __file__, __file__
        )

    with pytest.raises(SystemExit):
        sock.return_value.recvfrom.side_effect = (
            (json.dumps({"a": "b"}), None), SystemExit
        )
        r.cuckoo_rooter(
            socket_path , "group", __file__, __file__, __file__, __file__
        )

    nic_available = mock.MagicMock()
    mock.patch.dict(r.handlers, {"nic_available": nic_available}).start()
    nic_available.return_value = "foobar output"

    with pytest.raises(SystemExit):
        sock.return_value.recvfrom.side_effect = (
            (json.dumps({
                "command": "nic_available",
                "args": ["interface"],
            }), None), SystemExit
        )
        r.cuckoo_rooter(
            socket_path , "group", __file__, __file__, __file__, __file__
        )

    nic_available.assert_called_once_with("interface")
    sock.return_value.sendto.assert_called_once_with(json.dumps({
        "output": "foobar output",
        "exception": None,
    }), None)

def test_cuckoo_rooter():
    logging.basicConfig(level=logging.DEBUG)
    try:
        if is_linux():
            do_cuckoo_rooter()
    except:
        raise
    finally:
        mock.patch.stopall()
