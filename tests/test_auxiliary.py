# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import pytest
import subprocess
import tempfile

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
        return "", (
            "1 packet captured\n"
            "X packets captured\n"
            "1 packet dropped by kernel\n"
            "Y packets dropped by kernel\n"
            "1 packet received by filter\n"
            "Z packets received by filter\n"
        )

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
