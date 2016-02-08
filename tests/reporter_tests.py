# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import tempfile
from nose.tools import assert_equals

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.config import Config


class ReportMock(Report):
    def run(self, data):
        return

class ReportAlterMock(Report):
    """Corrupts results dict."""
    def run(self, data):
        data['foo'] = 'notbar'
        return
