# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import pytest
import tempfile

from sqlalchemy.exc import OperationalError

from cuckoo.core.database import Database, Sample, Task
from cuckoo.misc import set_cwd

class TestDropDatabase:
    """Tests database creation, adding a couple of tasks and dropping the db."""

    def setup(self):
        set_cwd(tempfile.mkdtemp())

        self.d = Database()
        self.d.connect(dsn="sqlite:///:memory:")

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
