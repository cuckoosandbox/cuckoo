# Copyright (C) 2016-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import errno
import json
import mock
import pytest
import socket
import tempfile

from cuckoo.apps import rooter as r
from cuckoo.core.rooter import rooter
from cuckoo.main import main, cuckoo_create
from cuckoo.misc import is_linux, set_cwd, version

if is_linux():
    @mock.patch("cuckoo.main.subprocess")
    def test_verbose_mode(p):
        main.main(("-d", "rooter", "--sudo"), standalone_mode=False)
        p.call.assert_called_once()
        assert p.call.call_args[0][0][:4] == [
            "sudo", mock.ANY, "--debug", "rooter",
        ]

def test_version():
    assert r.version() == {
        "version": version,
        "features": [],
    }

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

@mock.patch("cuckoo.apps.rooter.run")
def test_disable_nat(p):
    p.side_effect = [
        (None, None), (None, "error"),
    ]
    r.disable_nat("foo")
    assert p.call_count == 2
    assert p.call_list[0] == p.call_list[1]
    p.assert_any_call(
        None, "-t", "nat", "-D", "POSTROUTING", "-o", "foo", "-j", "MASQUERADE"
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
    with pytest.raises(SystemExit) as e:
        with mock.patch("__builtin__.__import__") as p:
            p.side_effect = ImportError
            r.cuckoo_rooter(None, None, None, None, None)
    e.match("not find the `grp` module")

    with pytest.raises(SystemExit) as e:
        r.cuckoo_rooter(None, None, None, None, None)
    e.match("service binary is not")

    with pytest.raises(SystemExit) as e:
        r.cuckoo_rooter(None, None, "DOES NOT EXIST", None, None)
    e.match("The service binary")

    with pytest.raises(SystemExit) as e:
        r.cuckoo_rooter(None, None, __file__, "DOES NOT EXIST", None)
    e.match("The `iptables` binary")

    with pytest.raises(SystemExit) as e:
        r.cuckoo_rooter(None, None, __file__, __file__, "DOES NOT EXIST")
    e.match("The `ip` binary")

    os_getuid = mock.patch("os.getuid").start()

    with pytest.raises(SystemExit) as e:
        os_getuid.return_value = 1000
        r.cuckoo_rooter(None, None, __file__, __file__, __file__)
    e.match("invoke it with the --sudo flag")

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

    with pytest.raises(SystemExit) as e:
        gr.side_effect = KeyError("foobar")
        r.cuckoo_rooter(socket_path, "group", __file__, __file__, __file__)
    e.match("Please define the group")

    gr.side_effect = None
    gr.return_value = gr_obj

    os_chown = mock.patch("os.chown").start()
    os_chown.return_value = None

    os_chmod = mock.patch("os.chmod").start()
    os_chmod.return_value = None

    with pytest.raises(SystemExit):
        sock.return_value.recvfrom.side_effect = SystemExit
        r.cuckoo_rooter(socket_path, "group", __file__, __file__, __file__)

    with pytest.raises(SystemExit):
        sock.return_value.recvfrom.side_effect = (
            ("this is not json", None), SystemExit
        )
        r.cuckoo_rooter(socket_path, "group", __file__, __file__, __file__)

    with pytest.raises(SystemExit):
        sock.return_value.recvfrom.side_effect = (
            (json.dumps({"a": "b"}), None), SystemExit
        )
        r.cuckoo_rooter(socket_path, "group", __file__, __file__, __file__)

    nic_available = mock.MagicMock()
    mock.patch.dict(r.handlers, {"nic_available": nic_available}).start()
    nic_available.return_value = "foobar output"

    with pytest.raises(SystemExit):
        sock.return_value.recvfrom.side_effect = (
            (json.dumps({
                "command": "nic_available",
                "args": ["interface"],
            }), None),
            socket.error(errno.EINTR, "such interrupt"),
            SystemExit
        )
        r.cuckoo_rooter(socket_path, "group", __file__, __file__, __file__)

    nic_available.assert_called_once_with("interface")
    sock.return_value.sendto.assert_called_once_with(json.dumps({
        "output": "foobar output",
        "exception": None,
    }), None)

def test_cuckoo_rooter():
    try:
        if is_linux():
            do_cuckoo_rooter()
    except:
        raise
    finally:
        mock.patch.stopall()

@mock.patch("cuckoo.core.rooter.os")
@mock.patch("cuckoo.core.rooter.lock")
@mock.patch("cuckoo.core.rooter.socket")
def test_rooter_client(p, q, r):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    s = p.socket.return_value
    s.recv.return_value = json.dumps({
        "exception": None,
        "output": "thisisoutput",
    })
    assert rooter(
        "command", "arg1", "arg2", arg3="foo", arg4="bar"
    ) == "thisisoutput"

    s.bind.assert_called_once()
    s.connect.assert_called_once_with("/tmp/cuckoo-rooter")
    s.send.assert_called_once_with(json.dumps({
        "command": "command",
        "args": (
            "arg1",
            "arg2",
        ),
        "kwargs": {
            "arg3": "foo",
            "arg4": "bar",
        }
    }))
    q.acquire.assert_called_once()
    q.release.assert_called_once()
