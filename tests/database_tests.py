# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import tempfile
from nose.tools import assert_equals

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.database import Database


class TestDatabase:
    def setUp(self):
        self.d = Database("sqlite:///:memory:")

    def test_add_path(self):
        tmp = tempfile.mkstemp()[1]
        assert_equals(1, self.d.add_path(file_path=tmp))
        os.remove(tmp)

    def test_add_url(self):
        assert_equals(1, self.d.add_url(url="http://foo.bar.com"))

    def test_add_file_not_found(self):
        assert_equals(None, self.d.add_path(file_path="foo"))

    def test_fetch(self):
        tmp = "http://foo.bar.com"
        assert_equals(1, self.d.add_url(url=tmp))
        assert_equals(tmp, self.d.fetch().target)

    def test_fetch_priority(self):
        tmp = "http://foo.bar.com"
        self.d.add_url(url=tmp, priority=2)
        self.d.add_url(url=tmp, priority=5)
        self.d.add_url(url=tmp, priority=4)
        assert_equals(2, self.d.fetch().id)
        assert_equals(2, self.d.fetch().id)

