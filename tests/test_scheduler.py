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
from cuckoo.core.database import Database
from cuckoo.core.log import task_log_stop
from cuckoo.core.scheduler import AnalysisManager, Scheduler, cuckoo
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
            self.sample_id = 1

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

class Test_am_LaunchAnalysis(object):
    class exp(object):
        def __init__(self):
            self.id = 2
            self.runs = 2
            self.times = 0

    class task(object):
        def __init__(self):
            self.id = 1234
            self.category = "file"
            self.target = __file__
            self.options = {}
            self.custom = None
            self.experiment_id = 1
            self.experiment = Test_am_LaunchAnalysis.exp()
            self.package = "py"
            self.memory = None

        def to_dict(self):
            return Dictionary(self.__dict__)

        def to_json(self):
            return json.dumps(self.to_dict())

    class machine(object):
        def __init__(self):
            self.ip = "1.2.3.4"
            self.interface = "vboxnet0"
            self.name = "machine1"
            self.options = {}
            self.label = "machine1"
            self.platform = "windows"

    @mock.patch("cuckoo.core.scheduler.Database")
    @mock.patch("cuckoo.core.scheduler.RunAuxiliary")
    @mock.patch("cuckoo.core.scheduler.ResultServer.add_task")
    @mock.patch("cuckoo.core.scheduler.ResultServer.del_task")
    @mock.patch("cuckoo.core.scheduler.GuestManager")
    def test_am_launch_analysis_task(self, mock_gm, mock_rs_del_task,
                                mock_rs_add_task, mock_ra, mock_db):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg=Dictionary({}))

        cuckoo.core.scheduler.machine_lock = mock.MagicMock()
        cuckoo.core.scheduler.machinery = mock.MagicMock()

        taskobj = Test_am_LaunchAnalysis.task()
        taskobj.experiment_id = None
        taskobj.experiment = None
        built_options = {}
        am = AnalysisManager(taskobj.id, None)
        am.task = taskobj
        am.machine = Test_am_LaunchAnalysis.machine()
        am.guest_manager = mock_gm

        am.init = mock.MagicMock(return_value=True)
        am.acquire_machine = mock.MagicMock()
        am.build_options = mock.MagicMock(return_value=built_options)
        am.route_network = mock.MagicMock()
        am.unroute_network = mock.MagicMock()
        am.guest_manage = mock.MagicMock()
        am.wait_finish = mock.MagicMock()
        am.aux = mock_ra
        am.db = mock_db

        # Start tested method
        succeeded = am.launch_analysis()

        am.init.assert_called_once()
        am.acquire_machine.assert_called_once()
        mock_rs_add_task.assert_called_once_with(am.task, am.machine)
        mock_gm.assert_called_once_with(am.machine.name, am.machine.ip,
                                        am.machine.platform, am.task.id, am)

        mock_ra.assert_called_once_with(am.task, am.machine, am.guest_manager)
        am.aux.start.assert_called_once()
        am.db.guest_start.assert_called_once_with(am.task.id, am.machine.name,
                                                  am.machine.label, mock.ANY)

        # This should be experiment: 0 because in this test the exp is
        # on its first run
        assert built_options == {}

        # Revert is true because it is not an experiment
        cuckoo.core.scheduler.machinery.start.assert_called_once_with(
            am.machine.label, am.task, revert=True
        )

        am.route_network.assert_called_once()
        cuckoo.core.scheduler.machine_lock.release.assert_called_once()
        am.guest_manage.assert_called_once_with(built_options)

        # Wait finish should not be called because guest manage is already
        # called
        am.wait_finish.assert_not_called()

        am.aux.stop.assert_called_once()

        # Stop should be called with safe=False because the machine
        # will be restored to a snapshot on next use
        cuckoo.core.scheduler.machinery.stop.assert_called_once_with(
            am.machine.label, safe=False
        )

        mock_rs_del_task.assert_called_once_with(am.task, am.machine)
        am.unroute_network.assert_called_once()
        am.db.guest_stop.assert_called_once()

        # No exp should be scheduled because this is not an experiment
        am.db.schedule_task_exp.assert_not_called()

        # Release should not be called because the machine is needed for the
        # next run of this experiment
        cuckoo.core.scheduler.machinery.release.assert_called_once_with(
            am.machine.label
        )

        assert succeeded == True

    @mock.patch("cuckoo.core.scheduler.Database")
    @mock.patch("cuckoo.core.scheduler.RunAuxiliary")
    @mock.patch("cuckoo.core.scheduler.ResultServer.add_task")
    @mock.patch("cuckoo.core.scheduler.ResultServer.del_task")
    @mock.patch("cuckoo.core.scheduler.GuestManager")
    def test_am_launch_analysis_exp(self, mock_gm, mock_rs_del_task,
                                mock_rs_add_task, mock_ra, mock_db):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg=Dictionary({}))

        cuckoo.core.scheduler.machine_lock = mock.MagicMock()
        cuckoo.core.scheduler.machinery = mock.MagicMock()

        taskobj = Test_am_LaunchAnalysis.task()
        built_options = {}
        am = AnalysisManager(taskobj.id, None)
        am.task = taskobj
        am.machine = Test_am_LaunchAnalysis.machine()
        am.guest_manager = mock_gm

        am.init = mock.MagicMock(return_value=True)
        am.acquire_machine = mock.MagicMock()
        am.build_options = mock.MagicMock(return_value=built_options)
        am.route_network = mock.MagicMock()
        am.unroute_network = mock.MagicMock()
        am.guest_manage = mock.MagicMock()
        am.wait_finish = mock.MagicMock()
        am.aux = mock_ra
        am.db = mock_db

        # Start tested method
        succeeded = am.launch_analysis()

        am.init.assert_called_once()
        am.acquire_machine.assert_called_once()
        mock_rs_add_task.assert_called_once_with(am.task, am.machine)
        mock_gm.assert_called_once_with(am.machine.name, am.machine.ip,
                                        am.machine.platform, am.task.id, am)

        mock_ra.assert_called_once_with(am.task, am.machine, am.guest_manager)
        am.aux.start.assert_called_once()
        am.db.guest_start.assert_called_once_with(am.task.id, am.machine.name,
                                                  am.machine.label, mock.ANY)

        # This should be experiment: 0 because in this test the exp is
        # on its first run
        assert built_options == {"experiment": 0}

        # Revert is true because it is the first run of an experiment
        cuckoo.core.scheduler.machinery.start.assert_called_once_with(
            am.machine.label, am.task, revert=True
        )

        am.route_network.assert_called_once()
        cuckoo.core.scheduler.machine_lock.release.assert_called_once()
        am.guest_manage.assert_called_once_with(built_options)

        # Wait finish should not be called because guest manage is already
        # called
        am.wait_finish.assert_not_called()

        am.aux.stop.assert_called_once()

        # Stop should be called with safe=True because the experiment
        # has runs left, meaning the OS should be shut down safely to be sure
        # changes are written to disk
        cuckoo.core.scheduler.machinery.stop.assert_called_once_with(
            am.machine.label, safe=True
        )

        mock_rs_del_task.assert_called_once_with(am.task, am.machine)
        am.unroute_network.assert_called_once()
        am.db.guest_stop.assert_called_once()

        # Schedule task exp should be called if the experiment has runs left
        am.db.schedule_task_exp.assert_called_once_with(am.task.id)

        # Release should not be called because the machine is needed for the
        # next run of this experiment
        cuckoo.core.scheduler.machinery.release.assert_not_called()

        assert succeeded == True

    @mock.patch("cuckoo.core.scheduler.Database")
    @mock.patch("cuckoo.core.scheduler.RunAuxiliary")
    @mock.patch("cuckoo.core.scheduler.ResultServer.add_task")
    @mock.patch("cuckoo.core.scheduler.ResultServer.del_task")
    @mock.patch("cuckoo.core.scheduler.GuestManager")
    def test_am_launch_analysis_exp_2d_run(self, mock_gm, mock_rs_del_task,
                                mock_rs_add_task, mock_ra, mock_db):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg=Dictionary({}))

        cuckoo.core.scheduler.machine_lock = mock.MagicMock()
        cuckoo.core.scheduler.machinery = mock.MagicMock()

        taskobj = Test_am_LaunchAnalysis.task()
        taskobj.experiment.times = 1
        built_options = {}
        am = AnalysisManager(taskobj.id, None)
        am.task = taskobj
        am.machine = Test_am_LaunchAnalysis.machine()
        am.guest_manager = mock_gm

        am.init = mock.MagicMock(return_value=True)
        am.acquire_machine = mock.MagicMock()
        am.build_options = mock.MagicMock(return_value=built_options)
        am.route_network = mock.MagicMock()
        am.unroute_network = mock.MagicMock()
        am.guest_manage = mock.MagicMock()
        am.wait_finish = mock.MagicMock()
        am.aux = mock_ra
        am.db = mock_db

        # Start tested method
        succeeded = am.launch_analysis()

        am.init.assert_called_once()
        am.acquire_machine.assert_called_once()
        mock_rs_add_task.assert_called_once_with(am.task, am.machine)
        mock_gm.assert_called_once_with(am.machine.name, am.machine.ip,
                                        am.machine.platform, am.task.id, am)

        mock_ra.assert_called_once_with(am.task, am.machine, am.guest_manager)
        am.aux.start.assert_called_once()
        am.db.guest_start.assert_called_once_with(am.task.id, am.machine.name,
                                                  am.machine.label, mock.ANY)

        # This should be experiment: 1 because in this test the exp is
        # on a second run. Experiment package should be used after the first
        # run of an experiment.
        assert built_options == {"experiment": 1, "package": "experiment"}

        # Revert is False because it is not the first run of this experiment
        cuckoo.core.scheduler.machinery.start.assert_called_once_with(
            am.machine.label, am.task, revert=False
        )

        am.route_network.assert_called_once()
        cuckoo.core.scheduler.machine_lock.release.assert_called_once()
        am.guest_manage.assert_called_once_with(built_options)

        # Wait finish should not be called because guest manage is already
        # called
        am.wait_finish.assert_not_called()

        am.aux.stop.assert_called_once()

        # Stop should be called with safe=True because the experiment
        # has runs left, meaning the OS should be shut down safely to be sure
        # changes are written to disk
        cuckoo.core.scheduler.machinery.stop.assert_called_once_with(
            am.machine.label, safe=True
        )

        mock_rs_del_task.assert_called_once_with(am.task, am.machine)
        am.unroute_network.assert_called_once()
        am.db.guest_stop.assert_called_once()

        # Schedule task exp should be called if the experiment has runs left
        am.db.schedule_task_exp.assert_called_once_with(am.task.id)

        # Release should not be called because the machine is needed for the
        # next run of this experiment
        cuckoo.core.scheduler.machinery.release.assert_not_called()

        assert succeeded == True

@mock.patch("cuckoo.core.scheduler.rooter")
def test_route_default_route(p):
    am = am_init({
    }, {
        "routing": {
            "routing": {
                "route": "internet",
                "internet": "nic0int",
                "rt_table": "nic0rt",
            },
        },
    })

    am.route_network()
    assert "route" not in am.task.options
    assert am.route == "internet"
    assert am.interface == "nic0int"
    assert am.rt_table == "nic0rt"
    assert p.call_count == 4

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
    p.assert_called_once_with("drop_enable", "1.2.3.4", "192.168.56.1", "2042")
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
    p.assert_called_once_with(
        "inetsim_enable", "1.2.3.4", "2.3.4.5", "vboxnet0", "2042"
    )
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
    p.assert_called_once_with(
        "tor_enable", "1.2.3.4", "192.168.56.1", "4242", "4141"
    )
    am.db.set_route.assert_called_once_with(1234, "tor")

@mock.patch("cuckoo.core.scheduler.rooter")
def test_route_internet_route(p):
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
    assert p.call_count == 4
    p.assert_any_call("nic_available", "nic0int")
    p.assert_any_call("drop_enable", "1.2.3.4", "192.168.56.1", "2042")
    p.assert_any_call("forward_enable", "vboxnet0", "nic0int", "1.2.3.4")
    p.assert_any_call("srcroute_enable", "nic0rt", "1.2.3.4")
    am.db.set_route.assert_called_once_with(1234, "internet")

@mock.patch("cuckoo.core.scheduler.rooter")
def test_route_internet_route_noconf(p):
    am = am_init({
        "route": "internet",
    }, {
        "routing": {
            "routing": {
                "rt_table": "nic0rt",
            },
        },
    })

    am.route_network()
    assert am.route == "none"
    assert am.interface is None
    assert am.rt_table is None
    p.assert_not_called()
    am.db.set_route.assert_called_once_with(1234, "none")

@mock.patch("cuckoo.core.scheduler.rooter")
def test_route_internet_unroute(p):
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

    am.route = "internet"
    am.interface = "nic0int"
    am.rt_table = "nic0rt"
    am.unroute_network()
    assert p.call_count == 3
    p.assert_any_call("drop_disable", "1.2.3.4", "192.168.56.1", "2042")
    p.assert_any_call("forward_disable", "vboxnet0", "nic0int", "1.2.3.4")
    p.assert_any_call("srcroute_disable", "nic0rt", "1.2.3.4")

@mock.patch("cuckoo.core.scheduler.rooter")
def test_route_vpn(p):
    am = am_init({
        "route": "vpn1",
    }, {
        "routing": {
            "vpn": {
                "enabled": True,
                "vpns": [
                    "vpn1",
                ],
            },
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
    p.assert_any_call("nic_available", "tun1")
    p.assert_any_call("forward_enable", "vboxnet0", "tun1", "1.2.3.4")
    p.assert_any_call("srcroute_enable", "tun1rt", "1.2.3.4")
    am.db.set_route.assert_called_once_with(1234, "vpn1")

@mock.patch("cuckoo.core.scheduler.rooter")
def test_scheduler_initialize(p):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "cuckoo": {
            "cuckoo": {
                "machinery": "machin3",
            },
        },
        "routing": {
            "routing": {
                "internet": "intern0t",
            },
            "vpn": {
                "enabled": True,
                "vpns": [
                    "a",
                ],
            },
            "a": {
                "name": "a",
                "interface": "vpnint0",
            },
        },
    })
    Database().connect()
    s = Scheduler()

    m = mock.MagicMock()
    m.return_value.machines.return_value = [
        Dictionary(name="cuckoo1", interface="int1", ip="1.2.3.4"),
        Dictionary(name="cuckoo2", interface="int2", ip="5.6.7.8"),
    ]

    with mock.patch.dict(cuckoo.machinery.plugins, {"machin3": m}):
        s.initialize()

    m.return_value.initialize.assert_called_once_with("machin3")
    assert p.call_count == 4
    p.assert_any_call("forward_disable", "int1", "vpnint0", "1.2.3.4")
    p.assert_any_call("forward_disable", "int2", "vpnint0", "5.6.7.8")
    p.assert_any_call("forward_disable", "int1", "intern0t", "1.2.3.4")
    p.assert_any_call("forward_disable", "int2", "intern0t", "5.6.7.8")

@mock.patch("cuckoo.core.scheduler.rooter")
def test_scheduler_initialize_novpn(p):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "cuckoo": {
            "cuckoo": {
                "machinery": "machin3",
            },
        },
    })
    Database().connect()
    s = Scheduler()

    m = mock.MagicMock()
    m.return_value.machines.return_value = [
        Dictionary(name="cuckoo1", interface="int1", ip="1.2.3.4"),
        Dictionary(name="cuckoo2", interface="int2", ip="5.6.7.8"),
    ]

    with mock.patch.dict(cuckoo.machinery.plugins, {"machin3": m}):
        s.initialize()

    m.return_value.initialize.assert_called_once_with("machin3")
    p.assert_not_called()
