# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import os
import pytest
import subprocess
import tempfile

from cuckoo.core.database import Database
from cuckoo.auxiliary.experiment import Experiment
from cuckoo.auxiliary.sniffer import Sniffer
from cuckoo.common.abstracts import Auxiliary
from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.misc import set_cwd, cwd, getuser, is_windows

def test_init():
    a = Auxiliary()
    a.set_options({
        "aux": "iliary",
    })
    assert a.options["aux"] == "iliary"
    assert a.options.aux == "iliary"

class BasePopen(object):
    pid = 0x4141

    def poll(self):
        return False

    def terminate(self):
        pass

    def communicate(self):
        return "", "X packets captured"

class PopenStdout(BasePopen):
    def communicate(self):
        return "stdout", "tcpdump: listening on foobar\nX packets captured\n"

class PopenStderr(BasePopen):
    def communicate(self):
        return "", "not a standard error message"

class PopenPermissionDenied(BasePopen):
    def poll(self):
        return True

class task(object):
    id = 42
    options = {}

class machine(object):
    interface = "interface"
    options = {}
    ip = "1.2.3.4"
    resultserver_ip = "1.1.1.1"
    resultserver_port = 1234

def test_sniffer():
    set_cwd(tempfile.mkdtemp())

    s = Sniffer()
    s.set_task(task)
    s.set_machine(machine)
    s.set_options({
        "tcpdump": __file__,
        "bpf": None,
    })

    with mock.patch("subprocess.Popen") as p:
        p.return_value = BasePopen()
        assert s.start() is True

    user = getuser()
    if user:
        user = "-Z %s " % user

    # Test regular setup.
    command = (
        "%s -U -q -s 0 -n -i interface %s-w %s "
        "host 1.2.3.4 and "
        "not ( dst host 1.2.3.4 and dst port 8000 ) and "
        "not ( src host 1.2.3.4 and src port 8000 ) and "
        "not ( dst host 1.1.1.1 and dst port 1234 ) and "
        "not ( src host 1.1.1.1 and src port 1234 )" % (
            __file__, user or "",
            cwd("storage", "analyses", "42", "dump.pcap")
        )
    )

    if is_windows():
        p.assert_called_once_with(
            command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
    else:
        p.assert_called_once_with(
            command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True
        )

    assert s.stop() is None

    # Test a bpf rule.
    s.options["bpf"] = "not arp"
    with mock.patch("subprocess.Popen") as p:
        p.return_value = BasePopen()
        assert s.start() is True

    if is_windows():
        p.assert_called_once_with(
            command.split() + ["and", "(", "not arp", ")"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
    else:
        p.assert_called_once_with(
            command.split() + ["and", "(", "not arp", ")"],
            close_fds=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

    assert s.stop() is None

    # Test an invalid executable path.
    with mock.patch("os.path.exists") as p:
        p.return_value = False
        assert s.start() is False

    # Test permission denied on tcpdump.
    with mock.patch("subprocess.Popen") as p:
        p.return_value = PopenPermissionDenied()
        assert s.start() is True

    with pytest.raises(CuckooOperationalError) as e:
        assert s.stop()
    e.match("the network traffic during the")
    e.match("denied-for-tcpdump")

    # Test stdout output from tcpdump.
    with mock.patch("subprocess.Popen") as p:
        p.return_value = PopenStdout()
        assert s.start() is True

    with pytest.raises(CuckooOperationalError) as e:
        assert s.stop()
    e.match("did not expect standard output")

    # Test unknown stderr output from tcpdump.
    with mock.patch("subprocess.Popen") as p:
        p.return_value = PopenStderr()
        assert s.start() is True

    with pytest.raises(CuckooOperationalError) as e:
        assert s.stop()
    e.match("following standard error output")

    # Test OSError and/or ValueError exceptions.
    with mock.patch("subprocess.Popen") as p:
        p.side_effect = OSError("this is awkward")
        assert s.start() is False

    with mock.patch("subprocess.Popen") as p:
        p.side_effect = ValueError("this is awkward")
        assert s.start() is False

class Exp_obj(object):
    id = 2
    last_completed = 1

class GuestManager(object):
    analyzer_path = "C:\\fTvYDijo"

    def post(self, method, files, data):
        return None

class TestExperiment(object):

    def setup_class(self):
        set_cwd(tempfile.mkdtemp())
        os.makedirs(cwd("storage", "analyses"))
        taskobj = task()
        taskobj.experiment = Exp_obj()
        taskobj.experiment_id = 2
        self.exp = Experiment()
        self.exp.set_task(taskobj)
        self.exp.set_guest_manager(GuestManager())
        self.task_folder = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "files", "sample_analysis_storage")
        Database().connect()

    def test_start_no_file(self):
        m = mock.MagicMock()
        m.list_tasks.return_value = [task()]

        with mock.patch("cuckoo.auxiliary.experiment.Database") as db:
            db.return_value = mock.MagicMock()
            db.side_effect = m
            self.exp.start()

        path = cwd("storage", "analyses", str(self.exp.task.id),
                   "experiment.json")

        assert not os.path.exists(path)

    def test_read_reboot(self):
        injectables = set()
        self.exp._read_reboot(self.task_folder, injectables)
        exepath = "C:\\Users\\Administrator\\AppData\\Local\\hkmsvc.exe"

        assert exepath in injectables

    def test_read_files(self):
        injectables = set()
        self.exp._read_files(self.task_folder, injectables)
        binpath = "C:\\Users\\Administrator\\AppData\\Roaming" \
                  "\\Adobe\\Acrobat\\9.0\\UserCache.bin"

        assert binpath in injectables

    def test_cb_prepare_guest(self):

        os.path.exists = mock.MagicMock(return_value=True)
        self.exp.guest_manager.post = mock.MagicMock(return_value=None)

        mocked_open = mock.mock_open(read_data="data")

        with mock.patch("__builtin__.open", mocked_open):
            self.exp.cb_prepare_guest()

        data = {
            "filepath": os.path.join(self.exp.guest_manager.analyzer_path,
                                       "experiment.json")
        }
        self.exp.guest_manager.post.assert_called_once_with(
            "/store", files=mock.ANY, data=data
        )
