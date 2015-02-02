# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import tempfile

from nose.tools import assert_equal, raises, assert_not_equal

from lib.cuckoo.core.database import Database, Machine, Sample, Task


class TestDatabase:

    def setUp(self):
        self.d = Database(dsn="sqlite://")

    def test_machine_add_clean(self):
        # Add.
        self.d.add_machine("a", "a", "1.1.1.1", "win", "", "", "", "", "")
        session = self.d.Session()
        assert_equal(session.query(Machine).count(), 1)
        # Delete.
        self.d.clean_machines()
        assert_equal(session.query(Machine).count(), 0)

    def test_task_add_del(self):
        # Add.
        sample_path = tempfile.mkstemp()[1]
        self.d.add_path(sample_path)
        session = self.d.Session()
        assert_equal(session.query(Sample).count(), 1)
        assert_equal(session.query(Task).count(), 1)
        # Drop tasks.
        self.d.drop_tasks()
        assert_equal(session.query(Task).count(), 0)
        assert_equal(session.query(Sample).count(), 1)
        # Drop samples.
        self.d.drop_samples()
        assert_equal(session.query(Sample).count(), 0)