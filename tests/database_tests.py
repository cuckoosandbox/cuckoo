# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import tempfile

from sqlalchemy.exc import OperationalError
from nose.tools import assert_equal, raises

from lib.cuckoo.core.database import Database, Sample, Task


class TestDropDatabase:
    """Tests database creation, adding a couple of tasks and dropping the db."""

    def setUp(self):
        self.d = Database(dsn="sqlite://")

    # When dropping a db, any other query raises a (OperationalError) no such table.
    @raises(OperationalError)
    def test_drop(self):
        # Add task.
        sample_path = tempfile.mkstemp()[1]
        self.d.add_path(sample_path)
        session = self.d.Session()
        assert_equal(session.query(Sample).count(), 1)
        assert_equal(session.query(Task).count(), 1)
        # Add url.
        self.d.add_url("http://foo.bar")
        assert_equal(session.query(Sample).count(), 1)
        assert_equal(session.query(Task).count(), 2)
        # Drop.
        self.d.drop()
        assert_equal(session.query(Task).count(), 0)