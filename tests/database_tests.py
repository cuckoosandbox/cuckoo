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

    def test_add(self):
        tmp = tempfile.mkstemp()[1]
        assert_equals(1, self.d.add(file_path=tmp))
        os.remove(tmp)

    def test_add_file_not_found(self):
        assert_equals(None, self.d.add(file_path="foo"))

    def test_fetch(self):
        tmp = tempfile.mkstemp()[1]
        assert_equals(1, self.d.add(file_path=tmp))
        assert_equals(tmp, self.d.fetch().file_path)
        os.remove(tmp)

    def test_lock(self):
        tmp = tempfile.mkstemp()[1]
        assert_equals(1, self.d.add(file_path=tmp))
        assert self.d.lock(1)
        os.remove(tmp)

    def test_unlock(self):
        tmp = tempfile.mkstemp()[1]
        assert_equals(1, self.d.add(file_path=tmp))
        assert self.d.lock(1)
        assert self.d.unlock(1)
        os.remove(tmp)

    def test_complete_success(self):
        tmp = tempfile.mkstemp()[1]
        assert_equals(1, self.d.add(file_path=tmp))
        assert self.d.complete(1, True)
        os.remove(tmp)
