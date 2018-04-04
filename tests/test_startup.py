# Copyright (C) 2017-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import json
import os
import pytest
import responses
import shutil
import subprocess
import sys
import tempfile

from cuckoo.common.abstracts import (
    Auxiliary, Machinery, Processing, Signature, Report
)
from cuckoo.common.exceptions import CuckooStartupError
from cuckoo.common.files import temppath
from cuckoo.common.objects import File
from cuckoo.core.database import Database
from cuckoo.core.startup import (
    init_modules, check_version, init_rooter, init_routing, init_yara,
    init_tasks, init_binaries, ensure_tmpdir
)
from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd, load_signatures, cwd, is_linux

def test_init_tasks():
    def init(reschedule):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "cuckoo": {
                "cuckoo": {
                    "reschedule": reschedule,
                },
            },
        })
        Database().connect()

        statuses = (
            "pending", "running", "completed", "reported"
        )

        tasks = []
        for status in statuses:
            task_id = Database().add_path(__file__)
            Database().set_status(task_id, status)
            tasks.append(task_id)

        init_tasks()

    init(True)
    assert Database().view_task(1).status == "pending"
    assert Database().view_task(2).status == "recovered"
    assert Database().view_task(3).status == "completed"
    assert Database().view_task(4).status == "reported"
    assert Database().view_task(5).status == "pending"
    assert Database().view_task(6) is None

    init(False)
    assert Database().view_task(1).status == "pending"
    assert Database().view_task(2).status == "failed_analysis"
    assert Database().view_task(3).status == "completed"
    assert Database().view_task(4).status == "reported"
    assert Database().view_task(5) is None

@mock.patch("cuckoo.core.startup.RunSignatures")
@mock.patch("cuckoo.reporting.elasticsearch.elastic")
@mock.patch("cuckoo.reporting.mongodb.mongo")
@mock.patch("cuckoo.core.startup.log")
def test_init_modules(p, q, r, s):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    load_signatures()

    logs = []

    def log(fmt, *args):
        logs.append(fmt % args if args else fmt)

    p.debug.side_effect = log
    r.index_time_pattern = "yearly"

    init_modules()
    s.init_once.assert_called_once()

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
def test_version_newer(capsys):
    set_cwd(tempfile.mkdtemp())
    responses.add(
        responses.GET, "https://cuckoosandbox.org/updates.json",
        status=200, json={
            "version": "20.0.0",
            "blogposts": [],
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
        responses.GET, "https://cuckoosandbox.org/updates.json",
        status=200, json={
            "version": "thisisnotaversion",
            "blogposts": [],
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
        responses.GET, "https://cuckoosandbox.org/updates.json",
        status=404
    )

    check_version()
    out, err = capsys.readouterr()
    assert "Checking for" in out
    assert "Error checking for" in out

@responses.activate
def test_version_respnotjson(capsys):
    set_cwd(tempfile.mkdtemp())
    responses.add(
        responses.GET, "https://cuckoosandbox.org/updates.json",
        status=200, body="thisisnotevenjson"
    )

    check_version()
    out, err = capsys.readouterr()
    assert "Checking for" in out
    assert "Error checking for" in out

class TestInitBinaries(object):
    def test_success(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()
        open(cwd("monitor", "latest"), "wb").write("A"*40)
        os.mkdir(cwd("monitor", "A"*40))
        init_binaries()

    def test_invalid_hash(self):
        open(cwd("monitor", "latest"), "wb").write("B"*40)
        with pytest.raises(CuckooStartupError):
            init_binaries()

    def test_empty_latest(self):
        open(cwd("monitor", "latest"), "wb").write("")
        with pytest.raises(CuckooStartupError):
            init_binaries()

    def test_latest_not_directory(self):
        os.unlink(cwd("monitor", "latest"))
        os.mkdir(cwd("monitor", "latest"))
        with pytest.raises(CuckooStartupError):
            init_binaries()

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

@mock.patch("cuckoo.core.startup.rooter")
def test_init_routing_vpns(p):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "routing": {
            "vpn": {
                "enabled": True,
                "vpns": [
                    "1", "2",
                ],
            },
            "1": {
                "name": "1",
                "interface": "tun1",
                "rt_table": "main",
            },
            "2": {
                "name": "2",
                "interface": "tun2",
                "rt_table": "main",
            },
        },
    })
    init_routing()
    assert p.call_count == 12
    p.assert_any_call("nic_available", "tun1")
    p.assert_any_call("rt_available", "main")
    p.assert_any_call("nic_available", "tun2")
    p.assert_any_call("disable_nat", "tun1")
    p.assert_any_call("disable_nat", "tun2")
    p.assert_any_call("enable_nat", "tun1")
    p.assert_any_call("enable_nat", "tun2")
    p.assert_any_call("flush_rttable", "main")
    p.assert_any_call("init_rttable", "main", "tun1")
    p.assert_any_call("init_rttable", "main", "tun2")

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

class TestYaraIntegration(object):
    def setup(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()

    def count(self, dirpath):
        ret = 0
        for name in os.listdir(dirpath):
            if name.endswith((".yar", ".yara")):
                ret += 1
        return ret

    def test_default(self):
        # Will change when we start shipping more Yara rules by default.
        assert self.count(cwd("yara", "binaries")) == 3
        assert not self.count(cwd("yara", "urls"))
        assert not self.count(cwd("yara", "memory"))

        init_yara()

        # This counts the amount of rules loaded, not files.
        assert len(list(File.yara_rules["binaries"])) == 5
        assert not list(File.yara_rules["urls"])
        assert not list(File.yara_rules["memory"])

    def test_invalid_rule(self):
        # TODO Cuckoo could help figuring out which Yara rule is the culprit,
        # but on the other hand, where's the fun in that?
        with pytest.raises(CuckooStartupError) as e:
            open(cwd("yara", "binaries", "invld.yar"), "wb").write("rule")
            init_yara()
        e.match("(unexpected _RULE_|unexpected \\$end)")

    def test_unreferenced_variable(self):
        # TODO This is probably a bit too harsh. Is it possible to suppress
        # such errors? Would the "error_on_warning" flag help here (we used
        # this flag in the past, btw)? Answer to the last question: probably
        # not provided it raises a SyntaxError rather than a WarningError (?).
        with pytest.raises(CuckooStartupError) as e:
            open(cwd("yara", "binaries", "invld.yar"), "wb").write("""
                rule a {
                    strings:
                      $s1 = "foo"
                      $s2 = "bar"
                    condition:
                      $s1
                }
            """)
            init_yara()
        e.match("unreferenced string")

    @pytest.mark.xfail
    def test_unicode(self):
        set_cwd(tempfile.mkdtemp(u"\u202e"))
        cuckoo_create()
        init_yara()
        assert len(list(File.yara_rules["binaries"])) == 5

    def test_symlink(self):
        if not is_linux():
            return

        # Include all Yara rules from binaries/ into memory/ as well.
        os.symlink(cwd("yara", "binaries"), cwd("yara", "memory", "bins"))
        init_yara()
        assert len(list(File.yara_rules["memory"])) == 5

    def test_stuff(self):
        open(cwd("yara", "memory", "hello.yara"), "wb").write("""
            rule A {
                condition:
                    1
            }
        """)
        init_yara()

        # $CWD/stuff/index_memory.yar
        assert os.path.exists(cwd("stuff", "index_memory.yar"))
        buf = open(cwd("stuff", "index_memory.yar"), "rb").read()
        assert 'include "%s"' % cwd("yara", "memory", "hello.yara") in buf

        # $CWD/stuff/dumpmem.yarac
        assert os.path.exists(cwd("stuff", "dumpmem.yarac"))
        assert os.path.getsize(cwd("stuff", "dumpmem.yarac")) > 2048

    def test_missing_category(self):
        File.yara_rules = {}
        shutil.rmtree(cwd("yara", "binaries"))
        init_yara()
        assert len(File.yara_rules) == 7
        assert not list(File.yara_rules["binaries"])

def test_tmp_permissions_true():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "cuckoo": {
            "cuckoo": {
                "tmppath": tempfile.mkdtemp(),
            }
        }
    })
    assert os.path.isdir(temppath())

@pytest.mark.skipif("sys.platform != 'linux2'")
def test_tmp_permissions_false():
    set_cwd(tempfile.mkdtemp())
    dirpath = tempfile.mkdtemp()
    cuckoo_create(cfg={
        "cuckoo": {
            "cuckoo": {
                "tmppath": dirpath,
            }
        }
    })
    os.chmod(dirpath, 0400)
    assert not ensure_tmpdir()

def test_light_startup():
    fetch_imports = (
        "import json, sys ; "
        "import cuckoo ; "
        "from cuckoo.main import main ; "
        "print json.dumps(sys.modules.keys())"
    )
    out, err = subprocess.Popen(
        [sys.executable, "-"], stdin=subprocess.PIPE, stdout=subprocess.PIPE
    ).communicate(fetch_imports)

    assert not err
    modules = json.loads(out)
    assert "androguard" not in modules
    assert "capstone" not in modules
    assert "django" not in modules
    assert "elasticsearch" not in modules
    assert "pkg_resources" not in modules
    assert "pymisp" not in modules
    assert "scapy" not in modules
    assert "weasyprint" not in modules
