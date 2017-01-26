# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import hashlib
import json
import mock
import os.path
import tempfile

from cuckoo.common.abstracts import Dictionary
from cuckoo.common.files import Folders
from cuckoo.core.log import task_log_stop
from cuckoo.core.scheduler import AnalysisManager
from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd, cwd

sha256_ = hashlib.sha256(open(__file__, "rb").read()).hexdigest()

def am_init(options={}, cfg={}):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg=cfg)

    class task(object):
        def __init__(self):
            self.id = 1234
            self.category = "file"
            self.target = __file__
            self.options = options

        def to_dict(self):
            return Dictionary(self.__dict__)

        def to_json(self):
            return json.dumps(self.to_dict())

    class sample(object):
        sha256 = sha256_

    class machine(object):
        ip = "1.2.3.4"
        interface = "vboxnet0"

    with mock.patch("cuckoo.core.scheduler.Database") as p:
        p.return_value.view_task.return_value = task()
        am = AnalysisManager(1234, None)
        am.machine = machine

        p.return_value.view_sample.return_value = sample()

    return am

def test_am_init_success():
    am = am_init()

    assert am.init() is True
    assert os.path.exists(cwd(analysis=1234))
    assert os.path.exists(cwd("storage", "binaries", sha256_))
    assert os.path.exists(cwd("binary", analysis=1234))

    # Manually disable per-task logging initiated by init().
    task_log_stop(1234)

def test_am_init_duplicate_analysis():
    am = am_init()

    Folders.create(cwd(analysis=1234))
    assert am.init() is False

    # Manually disable per-task logging initiated by init().
    task_log_stop(1234)

@mock.patch("cuckoo.core.scheduler.rooter")
def test_route_none(p):
    am = am_init({
        "route": "none",
    })

    am.route_network()
    assert am.route == "none"
    assert am.interface is None
    assert am.rt_table is None
    p.assert_not_called()
    am.db.set_route.assert_called_once_with(1234, "none")

@mock.patch("cuckoo.core.scheduler.rooter")
def test_route_drop(p):
    am = am_init({
        "route": "drop",
    })

    am.route_network()
    assert am.route == "drop"
    assert am.interface is None
    assert am.rt_table is None
    p.assert_called_once_with("drop_enable", "1.2.3.4", "2042")
    am.db.set_route.assert_called_once_with(1234, "drop")

@mock.patch("cuckoo.core.scheduler.rooter")
def test_route_inetsim(p):
    am = am_init({
        "route": "inetsim",
    }, {
        "routing": {
            "inetsim": {
                "server": "2.3.4.5",
            },
        },
    })

    am.route_network()
    assert am.route == "inetsim"
    assert am.interface is None
    assert am.rt_table is None
    p.assert_called_once_with("inetsim_enable", "1.2.3.4", "2.3.4.5", "2042")
    am.db.set_route.assert_called_once_with(1234, "inetsim")

@mock.patch("cuckoo.core.scheduler.rooter")
def test_route_tor(p):
    am = am_init({
        "route": "tor",
    }, {
        "routing": {
            "tor": {
                "dnsport": 4242,
                "proxyport": 4141,
            },
        },
    })

    am.route_network()
    assert am.route == "tor"
    assert am.interface is None
    assert am.rt_table is None
    p.assert_called_once_with("tor_enable", "1.2.3.4", "2042", "4242", "4141")
    am.db.set_route.assert_called_once_with(1234, "tor")

@mock.patch("cuckoo.core.scheduler.rooter")
def test_route_internet(p):
    am = am_init({
        "route": "internet",
    }, {
        "routing": {
            "routing": {
                "internet": "nic0int",
                "rt_table": "nic0rt",
            },
        },
    })

    am.route_network()
    assert am.route == "internet"
    assert am.interface == "nic0int"
    assert am.rt_table == "nic0rt"
    assert p.call_count == 3
    p.assert_any_call("nic_available", "nic0int")
    p.assert_any_call("forward_enable", "vboxnet0", "nic0int", "1.2.3.4")
    p.assert_any_call("srcroute_enable", "nic0rt", "1.2.3.4")
    am.db.set_route.assert_called_once_with(1234, "internet")

"""TODO Once a configuration writing tweak for "*" entries has been done.
@mock.patch("cuckoo.core.scheduler.rooter")
def test_route_vpn(p):
    am = am_init({
        "route": "vpn1",
    }, {
        "routing": {
            "vpn1": {
                "name": "vpn1",
                "description": "this is vpn1",
                "interface": "tun1",
                "rt_table": "tun1rt",
            },
        },
    })

    am.route_network()
    assert am.route == "vpn1"
    assert am.interface == "tun1"
    assert am.rt_table == "tun1rt"
    assert p.call_count == 3
    p.assert_any_call("nic_available", "nic0int")
    p.assert_any_call("forward_enable", "vboxnet0", "nic0int", "1.2.3.4")
    p.assert_any_call("srcroute_enable", "nic0rt", "1.2.3.4")
    am.db.set_route.assert_called_once_with(1234, "internet")
"""
