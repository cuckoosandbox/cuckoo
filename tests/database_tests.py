# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sqlite3
import tempfile
from nose.tools import assert_equals

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.database import Database


class TestDatabase:
    def setUp(self):
        self.tmp = os.path.join(tempfile.mkdtemp(), "dbtestcuckoo")
        self.d = Database(db_file=self.tmp)

    def test_db_path_default(self):
        """@note: Regression unit test."""
        d = Database()
        assert_equals(d.db_file, os.path.join(CUCKOO_ROOT, "db", "cuckoo.db"))
        assert os.path.exists(self.d.db_file)

    def test_db_path_custom(self):
        """@note: Regression unit test."""
        tmp = tempfile.mkstemp()[1]
        d = Database(db_file=tmp)
        assert_equals(d.db_file, tmp)
        assert os.path.exists(self.d.db_file)
        os.remove(tmp)

    def test_generate(self):
        conn = sqlite3.connect(self.tmp)
        cursor = conn.cursor()
        cursor.execute("SELECT count(name) FROM sqlite_master WHERE name='tasks';")
        assert_equals(1, cursor.fetchone()[0])

    def test_add(self):
        tmp = tempfile.mkstemp()[1]
        assert_equals(1, self.d.add(file_path=tmp))
        conn = sqlite3.connect(self.tmp)
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM tasks;")      
        assert_equals(1, cursor.fetchone()[0])
        os.remove(tmp)

    def test_add_file_not_found(self):
        assert_equals(None, self.d.add(file_path="foo"))

    def test_fetch(self):
        tmp = tempfile.mkstemp()[1]
        assert_equals(1, self.d.add(file_path=tmp))
        assert_equals(tmp, self.d.fetch()['file_path'])
        conn = sqlite3.connect(self.tmp)
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM tasks;")      
        assert_equals(1, cursor.fetchone()[0])
        os.remove(tmp)

    def test_lock(self):
        tmp = tempfile.mkstemp()[1]
        assert_equals(1, self.d.add(file_path=tmp))
        assert self.d.lock(1)
        conn = sqlite3.connect(self.tmp)
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM tasks WHERE lock=0;")      
        assert_equals(0, cursor.fetchone()[0])
        os.remove(tmp)

    def test_unlock(self):
        tmp = tempfile.mkstemp()[1]
        assert_equals(1, self.d.add(file_path=tmp))
        assert self.d.lock(1)
        conn = sqlite3.connect(self.tmp)
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM tasks WHERE lock=0;")      
        assert_equals(0, cursor.fetchone()[0])
        assert self.d.unlock(1)
        cursor.execute("SELECT count(*) FROM tasks WHERE lock=0;")      
        assert_equals(1, cursor.fetchone()[0])
        os.remove(tmp)

    def test_complete_success(self):
        tmp = tempfile.mkstemp()[1]
        assert_equals(1, self.d.add(file_path=tmp))
        assert self.d.complete(1, True)
        conn = sqlite3.connect(self.tmp)
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM tasks WHERE status=2;")      
        assert_equals(1, cursor.fetchone()[0])
        os.remove(tmp)

    def test_complete_fail(self):
        tmp = tempfile.mkstemp()[1]
        assert_equals(1, self.d.add(file_path=tmp))
        assert self.d.complete(1, False)
        conn = sqlite3.connect(self.tmp)
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM tasks WHERE status=1;")      
        assert_equals(1, cursor.fetchone()[0])
        os.remove(tmp)

    def tearDown(self):
        os.remove(self.tmp)