# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import pytest
import tempfile

from cuckoo.common import abstracts

class TestProcessing:
    def setup(self):
        self.p = abstracts.Processing()

    def test_not_implemented_run(self):
        with pytest.raises(NotImplementedError):
            self.p.run()

class TestReport:
    def setup(self):
        self.r = abstracts.Report()

    def test_set_path(self):
        dir = tempfile.mkdtemp()
        rep_dir = os.path.join(dir, "reports")
        self.r.set_path(dir)
        assert os.path.exists(rep_dir)
        os.rmdir(rep_dir)

    def test_options_none(self):
        assert self.r.options is None

    def test_set_options_assignment(self):
        foo = {1: 2}
        self.r.set_options(foo)
        assert foo == self.r.options

    def test_not_implemented_run(self):
        with pytest.raises(NotImplementedError):
            self.r.run({})
