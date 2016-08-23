# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cuckoo.common.abstracts import Report

class ReportMock(Report):
    def run(self, data):
        return

class ReportAlterMock(Report):
    """Corrupts results dict."""
    def run(self, data):
        data['foo'] = 'notbar'
        return
