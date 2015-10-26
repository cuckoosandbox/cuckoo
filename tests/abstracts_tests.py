# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import tempfile
from nose.tools import assert_equals, raises

import lib.cuckoo.common.abstracts as abstracts
from lib.cuckoo.common.config import Config


class TestProcessing:
    def setUp(self):
        self.p = abstracts.Processing()

    @raises(NotImplementedError)
    def test_not_implemented_run(self):
        self.p.run()

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
