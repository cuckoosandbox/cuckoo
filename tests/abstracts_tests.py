# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import tempfile
from nose.tools import assert_equals, raises

import lib.cuckoo.common.abstracts as abstracts
from lib.cuckoo.common.config import Config

class TestMachineManager:

    CONF_EXAMPLE = """
[kvm]
machines = cxp
[cxp]
label = cxp-k
platform = windows
ip = 192.168.122.27
"""

    CONF_EXAMPLE_MISSING_VM = """
[kvm]
machines = cxp, missing
[cxp]
label = cxp-k
platform = windows
ip = 192.168.122.27
"""

    def setUp(self):
        self.file = tempfile.mkstemp()[1]
        self.m = abstracts.MachineManager()
        self._load_conf(self.CONF_EXAMPLE)
        self.m._initialize("kvm")

    def _load_conf(self, conf):
        """Loads a configuration from a string.
        @param conf: configuration string.
        """
        f = open(self.file, "w")
        f.write(conf)
        f.close()
        self.m.set_options(Config(self.file))

    @raises(NotImplementedError)
    def test_not_implemented_start(self):
        self.m.start()

    @raises(NotImplementedError)
    def test_not_implemented_stop(self):
        self.m.stop()

    @raises(NotImplementedError)
    def test_not_implemented_list(self):
        self.m._list()

    def test_availables(self):
        assert isinstance(self.m.availables(), int)
        assert_equals(1, self.m.availables())

    def test_acquire_by_name(self):
        machine = self.m.acquire(machine_id="cxp")
        assert_equals(0, self.m.availables())
        self.m.release(machine.label)
        assert_equals(1, self.m.availables())

    def test_acquire_by_platform(self):
        machine = self.m.acquire(platform="windows")
        assert_equals(0, self.m.availables())
        self.m.release(machine.label)
        assert_equals(1, self.m.availables())

    def tearDown(self):
        os.remove(self.file)

class TestProcessing:
    def setUp(self):
        self.p = abstracts.Processing()

    @raises(NotImplementedError)
    def test_not_implemented_run(self):
        self.p.run()

class TestSignature(object):
    def setUp(self):
        self.s = abstracts.Signature()

    @raises(NotImplementedError)
    def test_not_implemented_run(self):
        self.s.run()

class TestReport:
    def setUp(self):
        self.r = abstracts.Report()
    
    def test_set_path(self):
        dir = tempfile.mkdtemp()
        rep_dir = os.path.join(dir, "reports")
        self.r.set_path(dir)
        assert os.path.exists(rep_dir)
        os.rmdir(rep_dir)

    def test_options_none(self):
        assert_equals(None, self.r.options)

    def test_set_options_assignment(self):
        foo = {1: 2}
        self.r.set_options(foo)
        assert_equals(foo, self.r.options)

    @raises(NotImplementedError)
    def test_not_implemented_run(self):
        self.r.run()
