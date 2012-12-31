# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import tempfile
from nose.tools import assert_equals

from lib.cuckoo.core.reporter import Reporter
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.config import Config


class TestReporter:
    CONFIG = """
[reporter_tests]
enabled = on
"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cfg = tempfile.mkstemp()[1]
        f = open(self.cfg, "w")
        f.write(self.CONFIG)
        f.close()
        self.r = Reporter(self.tmp)
        self.r.cfg = Config(self.cfg)

    def test_run_report(self):
        results = {}
        self.r._run_report(ReportMock, results)

    def test_run_report_alter_results(self):
        """@note: Regression test."""
        results = {"foo": "bar"}
        self.r._run_report(ReportAlterMock, results)
        assert_equals(results, {"foo": "bar"})

    def tearDown(self):
        os.rmdir(os.path.join(self.tmp, "reports"))
        os.rmdir(self.tmp)
        os.remove(self.cfg)

class ReportMock(Report):
    def run(self, data):
        return

class ReportAlterMock(Report):
    """Corrupts results dict."""
    def run(self, data):
        data['foo'] = 'notbar'
        return