# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import os
import pytest
import tempfile

from cuckoo.core.database import Database, Task, AlembicVersion, SCHEMA_VERSION
from cuckoo.main import main, cuckoo_create
from cuckoo.misc import set_cwd, cwd

class DatabaseEngine(object):
    """Tests database stuff."""
    URI = None

    def setup_class(self):
        set_cwd(tempfile.mkdtemp())

        self.d = Database()
        self.d.connect(dsn=self.URI)

    def add_url(self, url, priority=1, status="pending"):
        task_id = self.d.add_url(url, priority=priority)
        self.d.set_status(task_id, status)
        return task_id

    def test_add_tasks(self):
        fd, sample_path = tempfile.mkstemp()
        os.write(fd, "hehe")
        os.close(fd)

        # Add task.
        count = self.d.Session().query(Task).count()
        self.d.add_path(sample_path)
        assert self.d.Session().query(Task).count() == count + 1

        # Add url.
        self.d.add_url("http://foo.bar")
        assert self.d.Session().query(Task).count() == count + 2

    def test_processing_get_task(self):
        # First reset all existing rows so that earlier exceptions don't affect
        # this unit test run.
        null, session = None, self.d.Session()

        session.query(Task).filter(
            Task.status == "completed", Task.processing == null
        ).update({
            "processing": "something",
        })
        session.commit()

        t1 = self.add_url("http://google.com/1", priority=1, status="completed")
        t2 = self.add_url("http://google.com/2", priority=2, status="completed")
        t3 = self.add_url("http://google.com/3", priority=1, status="completed")
        t4 = self.add_url("http://google.com/4", priority=1, status="completed")
        t5 = self.add_url("http://google.com/5", priority=3, status="completed")
        t6 = self.add_url("http://google.com/6", priority=1, status="completed")
        t7 = self.add_url("http://google.com/7", priority=1, status="completed")

        assert self.d.processing_get_task("foo") == t5
        assert self.d.processing_get_task("foo") == t2
        assert self.d.processing_get_task("foo") == t1
        assert self.d.processing_get_task("foo") == t3
        assert self.d.processing_get_task("foo") == t4
        assert self.d.processing_get_task("foo") == t6
        assert self.d.processing_get_task("foo") == t7
        assert self.d.processing_get_task("foo") is None

    def test_error_exists(self):
        task_id = self.add_url("http://google.com/")
        self.d.add_error("A"*1024, task_id)
        assert len(self.d.view_errors(task_id)) == 1
        self.d.add_error("A"*1024, task_id)
        assert len(self.d.view_errors(task_id)) == 2

    def test_long_error(self):
        self.add_url("http://google.com/")
        self.d.add_error("A"*1024, 1)
        err = self.d.view_errors(1)
        assert err and len(err[0].message) == 1024

    def test_submit(self):
        dirpath = tempfile.mkdtemp()
        submit_id = self.d.add_submit(dirpath, "files", {
            "foo": "bar",
        })
        submit = self.d.view_submit(submit_id)
        assert submit.id == submit_id
        assert submit.tmp_path == dirpath
        assert submit.submit_type == "files"
        assert submit.data == {
            "foo": "bar",
        }

    def test_connect_no_create(self):
        AlembicVersion.__table__.drop(self.d.engine)
        self.d.connect(dsn=self.URI, create=False)
        assert "alembic_version" not in self.d.engine.table_names()
        self.d.connect(dsn=self.URI)
        assert "alembic_version" in self.d.engine.table_names()

class TestConnectOnce(object):
    def setup(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()

    @mock.patch("cuckoo.main.Database")
    @mock.patch("cuckoo.apps.apps.Database")
    @mock.patch("cuckoo.apps.apps.process")
    def test_process_task(self, q, p1, p2):
        main.main(
            ("--cwd", cwd(), "process", "-r", "1"),
            standalone_mode=False
        )

        q.assert_called_once()
        p2.return_value.connect.assert_called_once()
        p1.return_value.connect.assert_not_called()

    @mock.patch("cuckoo.main.Database")
    @mock.patch("cuckoo.apps.apps.Database")
    @mock.patch("cuckoo.apps.apps.process")
    def test_process_tasks(self, q, p1, p2):
        p1.return_value.processing_get_task.side_effect = 1, 2
        p1.return_value.view_task.side_effect = [
            Task(id=1, category="url", target="http://google.com/"),
            Task(id=2, category="url", target="http://google.nl/"),
        ]

        main.main(
            ("--cwd", cwd(), "process", "p0"),
            standalone_mode=False
        )

        assert q.call_count == 2
        p2.return_value.connect.assert_called_once()
        p1.return_value.connect.assert_not_called()

class TestSqlite3Memory(DatabaseEngine):
    URI = "sqlite:///:memory:"

class TestSqlite3File(DatabaseEngine):
    URI = "sqlite:///%s" % tempfile.mktemp()

class TestPostgreSQL(DatabaseEngine):
    URI = "postgresql://cuckoo:cuckoo@localhost/cuckootest"

class TestMySQL(DatabaseEngine):
    URI = "mysql://cuckoo:cuckoo@localhost/cuckootest"

@pytest.mark.skipif("sys.platform != 'linux2'")
class DatabaseMigrationEngine(object):
    """Tests database migration(s)."""
    URI = None
    SRC = None

    def setup_class(cls):
        set_cwd(tempfile.mkdtemp())

        cls.d = Database()
        cls.d.connect(dsn=cls.URI, create=False)

        cuckoo_create(cfg={
            "cuckoo": {
                "database": {
                    "connection": cls.URI,
                },
            },
        })

        cls.s = cls.d.Session()
        cls.execute_script(cls, open(cls.SRC, "rb").read())
        cls.migrate(cls)

    def test_alembic_version(self):
        version = self.s.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchall()
        assert version and len(version) == 1
        assert version[0][0] == SCHEMA_VERSION

    def test_long_error(self):
        task_id = self.d.add_url("http://google.com/")
        self.d.add_error("A"*1024, task_id)
        err = self.d.view_errors(task_id)
        assert err and len(err[0].message) == 1024

class DatabaseMigration060(DatabaseMigrationEngine):
    def test_machine_resultserver_port_is_int(self):
        machines = self.s.execute(
            "SELECT resultserver_ip, resultserver_port FROM machines"
        ).fetchall()
        assert machines and len(machines) == 2
        assert machines[0][0] == "192.168.56.1"
        assert machines[0][1] == 2042
        assert machines[1][0] == "192.168.56.1"
        assert machines[1][1] == 2042

class TestDatabaseMigration060PostgreSQL(DatabaseMigration060):
    URI = "postgresql://cuckoo:cuckoo@localhost/cuckootest060"
    SRC = "tests/files/sql/060pg.sql"

    @staticmethod
    def execute_script(cls, script):
        cls.s.execute(script)
        cls.s.commit()

    @staticmethod
    def migrate(cls):
        tasks = cls.d.engine.execute(
            "SELECT status FROM tasks ORDER BY id"
        ).fetchall()
        assert tasks[0][0] == "failure"
        assert tasks[1][0] == "success"
        assert tasks[2][0] == "processing"

        main.main(
            ("--cwd", cwd(), "migrate", "--revision", "263a45963c72"),
            standalone_mode=False
        )

        tasks = cls.d.engine.execute(
            "SELECT status FROM tasks ORDER BY id"
        ).fetchall()
        assert tasks[0][0] == "failed_analysis"
        assert tasks[1][0] == "completed"
        assert tasks[2][0] == "running"

        main.main(
            ("--cwd", cwd(), "migrate"),
            standalone_mode=False
        )

        tasks = cls.d.engine.execute(
            "SELECT status, owner FROM tasks ORDER BY id"
        ).fetchall()
        assert tasks[0][0] == "failed_analysis"
        assert tasks[0][1] is None
        assert tasks[1][0] == "completed"
        assert tasks[2][0] == "running"

class TestDatabaseMigration060SQLite3(DatabaseMigration060):
    URI = "sqlite:///%s.sqlite3" % tempfile.mktemp()
    SRC = "tests/files/sql/060sq.sql"

    @staticmethod
    def execute_script(cls, script):
        cls.s.connection().connection.cursor().executescript(script)

    @staticmethod
    def migrate(cls):
        tasks = cls.d.engine.execute(
            "SELECT status FROM tasks ORDER BY id"
        ).fetchall()
        assert tasks[0][0] == "failure"
        assert tasks[1][0] == "processing"
        assert tasks[2][0] == "success"
        assert tasks[3][0] == "pending"

        main.main(
            ("--cwd", cwd(), "migrate", "--revision", "263a45963c72"),
            standalone_mode=False
        )

        tasks = cls.d.engine.execute(
            "SELECT status FROM tasks ORDER BY id"
        ).fetchall()
        assert tasks[0][0] == "failed_analysis"
        assert tasks[1][0] == "running"
        assert tasks[2][0] == "completed"
        assert tasks[3][0] == "pending"

        main.main(
            ("--cwd", cwd(), "migrate"),
            standalone_mode=False
        )

        tasks = cls.d.engine.execute(
            "SELECT status, owner FROM tasks ORDER BY id"
        ).fetchall()
        assert tasks[0][0] == "failed_analysis"
        assert tasks[0][1] is None
        assert tasks[1][0] == "running"
        assert tasks[2][0] == "completed"
        assert tasks[3][0] == "pending"

class TestDatabaseMigration060MySQL(DatabaseMigration060):
    URI = "mysql://cuckoo:cuckoo@localhost/cuckootest060"
    SRC = "tests/files/sql/060my.sql"

    @staticmethod
    def execute_script(cls, script):
        cls.s.execute(script)

    @staticmethod
    def migrate(cls):
        tasks = cls.d.engine.execute(
            "SELECT status FROM tasks ORDER BY id"
        ).fetchall()
        assert tasks[0][0] == "success"
        assert tasks[1][0] == "processing"
        assert tasks[2][0] == "pending"

        main.main(
            ("--cwd", cwd(), "migrate", "--revision", "263a45963c72"),
            standalone_mode=False
        )

        tasks = cls.d.engine.execute(
            "SELECT status FROM tasks ORDER BY id"
        ).fetchall()
        assert tasks[0][0] == "completed"
        assert tasks[1][0] == "running"
        assert tasks[2][0] == "pending"

        main.main(
            ("--cwd", cwd(), "migrate"),
            standalone_mode=False
        )

        tasks = cls.d.engine.execute(
            "SELECT status, owner FROM tasks ORDER BY id"
        ).fetchall()
        assert tasks[0][0] == "completed"
        assert tasks[0][1] is None
        assert tasks[1][0] == "running"
        assert tasks[2][0] == "pending"

class DatabaseMigration11(DatabaseMigrationEngine):
    @staticmethod
    def migrate(cls):
        main.main(("--cwd", cwd(), "migrate"), standalone_mode=False)

    def test_task_statuses(cls):
        tasks = cls.d.engine.execute(
            "SELECT status, owner FROM tasks ORDER BY id"
        ).fetchall()
        assert tasks[0][0] == "reported"
        assert tasks[1][0] == "pending"

class TestDatabaseMigration11PostgreSQL(DatabaseMigration11):
    URI = "postgresql://cuckoo:cuckoo@localhost/cuckootest11"
    SRC = "tests/files/sql/11pg.sql"

    @staticmethod
    def execute_script(cls, script):
        cls.s.execute(script)
        cls.s.commit()

class TestDatabaseMigration11SQLite3(DatabaseMigration11):
    URI = "sqlite:///%s.sqlite3" % tempfile.mktemp()
    SRC = "tests/files/sql/11sq.sql"

    @staticmethod
    def execute_script(cls, script):
        cls.s.connection().connection.cursor().executescript(script)

class TestDatabaseMigration11MySQL(DatabaseMigration11):
    URI = "mysql://cuckoo:cuckoo@localhost/cuckootest11"
    SRC = "tests/files/sql/11my.sql"

    @staticmethod
    def execute_script(cls, script):
        cls.s.execute(script)

@mock.patch("cuckoo.core.database.create_engine")
@mock.patch("cuckoo.core.database.sessionmaker")
def test_connect_default(p, q):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    db = Database()
    db.connect(create=False)
    q.assert_called_once_with(
        "sqlite:///%s" % cwd("cuckoo.db"),
        connect_args={"check_same_thread": False}
    )
    assert db.engine.pool_timeout == 60

@mock.patch("cuckoo.core.database.create_engine")
@mock.patch("cuckoo.core.database.sessionmaker")
def test_connect_pg(p, q):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "cuckoo": {
            "database": {
                "connection": "postgresql://foo:bar@localhost/foobar",
                "timeout": 120,
            }
        }
    })

    db = Database()
    db.connect(create=False)
    q.assert_called_once_with(
        "postgresql://foo:bar@localhost/foobar",
        connect_args={"sslmode": "disable"}
    )
    assert db.engine.pool_timeout == 120
