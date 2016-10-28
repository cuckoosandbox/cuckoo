# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import pytest
import tempfile

from sqlalchemy.exc import OperationalError

from cuckoo.core.database import Database, Sample, Task
from cuckoo.misc import set_cwd

class TestDatabase:
    """Tests database stuff."""

    def setup(self):
        set_cwd(tempfile.mkdtemp())

        self.d = Database()
        self.d.connect(dsn="sqlite:///:memory:")

    def add_url(self, url, priority=1, status="pending"):
        task_id = self.d.add_url(url, priority=priority)
        self.d.set_status(task_id, status)
        return task_id

    def test_drop(self):
        # Add task.
        sample_path = tempfile.mkstemp()[1]
        self.d.add_path(sample_path)
        session = self.d.Session()
        assert session.query(Sample).count() == 1
        assert session.query(Task).count() == 1

        # Add url.
        self.d.add_url("http://foo.bar")
        assert session.query(Sample).count() == 1
        assert session.query(Task).count() == 2

        # Drop.
        self.d.drop()

        # After dropping a database, any other query raises a OperationalError
        # exception; "no such table".
        with pytest.raises(OperationalError):
            assert session.query(Task).count() == 0

    def test_processing_get_task(self):
        self.add_url("http://google.com/1", priority=1, status="completed")
        self.add_url("http://google.com/2", priority=2, status="completed")
        self.add_url("http://google.com/3", priority=1, status="completed")
        self.add_url("http://google.com/4", priority=1, status="completed")
        self.add_url("http://google.com/5", priority=3, status="completed")
        self.add_url("http://google.com/6", priority=1, status="completed")
        self.add_url("http://google.com/7", priority=1, status="completed")

        assert self.d.processing_get_task("foo") == 5
        assert self.d.processing_get_task("foo") == 2
        assert self.d.processing_get_task("foo") == 1
        assert self.d.processing_get_task("foo") == 3
        assert self.d.processing_get_task("foo") == 4
        assert self.d.processing_get_task("foo") == 6
        assert self.d.processing_get_task("foo") == 7
        assert self.d.processing_get_task("foo") is None

    def test_error_exists(self):
        self.add_url("http://google.com/")
        self.d.add_error("A"*1024, 1)
        assert self.d.view_errors(1)

    @pytest.mark.xfail(strict=True)
    def test_long_error(self):
        self.add_url("http://google.com/")
        self.d.add_error("A"*1024, 1)
        err = self.d.view_errors(1)
        assert err and len(err[0].message) == 1024
