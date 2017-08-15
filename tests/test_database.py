# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import mock
import os
import pytest
import tempfile

from sqlalchemy.orm.exc import DetachedInstanceError
from sqlalchemy.orm import lazyload

from cuckoo.common.files import Files
from cuckoo.core.database import (
    Database, Task, AlembicVersion, SCHEMA_VERSION, Experiment
)
from cuckoo.core.startup import index_yara
from cuckoo.distributed.app import create_app
from cuckoo.main import main, cuckoo_create
from cuckoo.misc import set_cwd, cwd, mkdir

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

    def create_file(self):
        fd, sample_path = tempfile.mkstemp()
        os.write(fd, os.urandom(24))
        os.close(fd)

        return sample_path

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

    def test_add_path_experiment(self):
        name = "tosti"
        runs = 2
        delta = "14h10m"

        # Add task with experiment enabled and retrieve it
        ses = self.d.Session()
        count = ses.query(Experiment).count()
        task_id = self.d.add_path(self.create_file(), experiment=True, name=name,
                                  runs=runs, delta=delta)

        task = ses.query(Task).get(task_id)
        exp = ses.query(Experiment).get(task.experiment_id)

        assert self.d.Session().query(Experiment).count() == count + 1
        assert exp.name == name
        assert exp.runs == runs
        assert exp.times == 0
        assert exp.delta == delta
        assert exp.id == task.experiment_id

    def test_add_url_experiment(self):
        name = "tosti_url"
        runs = 7
        delta = "24h"
        url = "http://google.com/"

        # Add task with experiment enabled and retrieve it
        ses = self.d.Session()
        count = ses.query(Experiment).count()
        task_id = self.d.add_url(url, experiment=True, name=name,
                                  runs=runs, delta=delta)

        task = ses.query(Task).get(task_id)
        exp = ses.query(Experiment).get(task.experiment_id)

        assert self.d.Session().query(Experiment).count() == count + 1
        assert exp.name == name
        assert exp.runs == runs
        assert exp.times == 0
        assert exp.delta == delta
        assert exp.id == task.experiment_id

    def test_view_experiment(self):
        task_id = self.d.add_path(self.create_file(), experiment=True,
                                  name="viewexp_test", runs=78,
                                  delta="19d")

        task = self.d.view_task(task_id)
        exp = self.d.view_experiment(id=task.experiment_id)

        assert exp.name == "viewexp_test"
        assert exp.delta == "19d"
        assert exp.runs == 78

    def test_update_experiment(self):
        task_id = self.d.add_path(self.create_file(), experiment=True,
                                  name="doges42", runs=1, delta="19d1h45m3s")
        task = self.d.view_task(task_id)
        exp = self.d.view_experiment(id=task.experiment_id)

        self.d.update_experiment(None, id=task.experiment_id, runs=0, times=1,
                                 timeout=1337, last_task_completed=10)
        exp_u = self.d.view_experiment(id=task.experiment_id)
        task_u = self.d.view_task(task_id)

        assert exp_u.name == exp.name
        assert exp_u.runs == 0
        assert exp_u.times == 1
        assert exp_u.last_completed == 10
        assert task_u.timeout == 1337

    def test_delete_experiment(self):
        task_id = self.d.add_path(self.create_file(), experiment=True,
                                  name="kaastosti", runs=10, delta="15m7s")

        task = self.d.view_task(task_id)
        self.d.delete_experiment(task.experiment_id)

        exp_d = self.d.view_experiment(id=task.experiment_id)
        task_d = self.d.view_task(task_id)

        assert exp_d is None
        assert task_d.experiment_id is None

    def test_list_tasks(self):

        # Get list of all current tasks to compare later
        task_list = self.d.list_tasks()
        task_id = self.d.add_path(self.create_file(), experiment=True,
                        name="list_tasks1", runs=3)
        task_exp = self.d.view_task(task_id)
        task_id_1 = self.d.add_path(self.create_file(), owner="Doge")
        self.add_url("https://google.com/")
        task_id_2 = self.d.add_path(self.create_file())
        self.d.set_status(task_id_2, "running")
        task_id_3 = self.d.add_path(self.create_file())
        self.d.set_status(task_id_3, "reported")

        assert len(task_list) + 5 == len(self.d.list_tasks())
        assert len(self.d.list_tasks(limit=2)) == 2
        assert task_id_1 == self.d.list_tasks(owner="Doge")[0].id
        assert task_id == self.d.list_tasks(sample_id=task_exp.sample_id)[0].id
        assert task_id == self.d.list_tasks(
            experiment=task_exp.experiment_id
        )[0].id

        # Verify if only the category file is among results
        assert len([
               s for s in self.d.list_tasks(category="file")
               if s.category != "file"
        ]) == 0
        # Verify if results only contain reported status
        assert len([
                s for s in self.d.list_tasks(status="reported")
                if s.status != "reported"
        ]) == 0
        # Verify if status running is not amongst results
        assert len([
                s for s in self.d.list_tasks(not_status="running")
                if s.status == "running"
        ]) == 0

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

    def test_view_submit_tasks(self):
        submit_id = self.d.add_submit(None, None, None)
        t1 = self.d.add_path(__file__, custom="1", submit_id=submit_id)
        t2 = self.d.add_path(__file__, custom="2", submit_id=submit_id)

        submit = self.d.view_submit(submit_id)
        assert submit.id == submit_id
        with pytest.raises(DetachedInstanceError):
            print submit.tasks

        submit = self.d.view_submit(submit_id, tasks=True)
        assert len(submit.tasks) == 2
        tasks = sorted((task.id, task) for task in submit.tasks)
        assert tasks[0][1].id == t1
        assert tasks[0][1].custom == "1"
        assert tasks[1][1].id == t2
        assert tasks[1][1].custom == "2"

    def test_add_reboot(self):
        t0 = self.d.add_path(__file__)
        s0 = self.d.add_submit(None, None, None)
        t1 = self.d.add_reboot(task_id=t0, submit_id=s0)

        t = self.d.view_task(t1)
        assert t.custom == "%s" % t0
        assert t.submit_id == s0

    def test_task_set_options(self):
        t0 = self.d.add_path(__file__, options={"foo": "bar"})
        t1 = self.d.add_path(__file__, options="foo=bar")
        assert self.d.view_task(t0).options == {"foo": "bar"}
        assert self.d.view_task(t1).options == {"foo": "bar"}

    def test_task_tags_str(self):
        task = self.d.add_path(__file__, tags="foo,,bar")
        tag0, tag1 = self.d.view_task(task).tags
        assert sorted((tag0.name, tag1.name)) == ["bar", "foo"]

    def test_task_tags_list(self):
        task = self.d.add_path(__file__, tags=["tag1", "tag2", "", 1, "tag3"])
        tag0, tag1, tag2 = self.d.view_task(task).tags
        assert sorted((tag0.name, tag1.name, tag2.name)) == [
            "tag1", "tag2", "tag3"
        ]

    def test_error_action(self):
        task_id = self.d.add_path(__file__)
        self.d.add_error("message1", task_id)
        self.d.add_error("message2", task_id, "actionhere")
        e1, e2 = self.d.view_errors(task_id)
        assert e1.message == "message1"
        assert e1.action is None
        assert e2.message == "message2"
        assert e2.action == "actionhere"

    def test_view_task(self):
        t1 = self.d.add_path(__file__, tags=["tag1", "tag2"])
        t2 = self.d.add_path(__file__, experiment=True, name="exp1",
                             runs=17, delta="1h")

        view1 = self.d.view_task(t1)
        view2 = self.d.view_task(t2)

        assert view1.tags is not None
        assert view2.experiment is not None

    def test_view_tasks(self):
        t1 = self.d.add_path(__file__)
        t2 = self.d.add_url("http://google.com/")
        t3 = self.d.add_path(__file__, experiment=True, name="exp2",
                                  runs=2, delta="1h")
        tasks = self.d.view_tasks([t1, t2, t3])

        assert tasks[0].to_dict() == self.d.view_task(t1).to_dict()
        assert tasks[1].to_dict() == self.d.view_task(t2).to_dict()
        assert tasks[1].experiment is None
        assert tasks[2].to_dict() == self.d.view_task(t3).to_dict()

    def test_list_machines(self):

        for n in range(1, 5):
            label = "tosti%s" % n
            self.d.add_machine(
                label, label, "1.2.3.4", "windows", None,
                "tag1 tag2", "int0", "snap0", "5.6.7.8", 2043
            )

        self.d.set_machine_status("tosti1", "running")
        self.d.set_machine_status("tosti2", "poweroff")
        self.d.set_machine_status("tosti3", "poweroff")
        self.d.set_machine_status("tosti3", "poweroff")
        self.d.lock_machine(label="tosti1")
        self.d.lock_machine(label="tosti2")

        all = self.d.list_machines()
        locked = self.d.list_machines(locked=True)
        running = self.d.list_machines(status="running")

        assert len(all) == 4
        assert len(locked) == 2
        assert len(running) == 1
        assert running[0].name == "tosti1"

    def test_add_machine(self):
        self.d.add_machine(
            "name1", "label", "1.2.3.4", "windows", None,
            "tag1 tag2", "int0", "snap0", "5.6.7.8", 2043
        )
        self.d.add_machine(
            "name2", "label", "1.2.3.4", "windows", "",
            "tag1 tag2", "int0", "snap0", "5.6.7.8", 2043
        )
        self.d.add_machine(
            "name3", "label", "1.2.3.4", "windows", "opt1 opt2",
            "tag1 tag2", "int0", "snap0", "5.6.7.8", 2043
        )
        self.d.add_machine(
            "name4", "label", "1.2.3.4", "windows", ["opt3", "opt4"],
            "tag1 tag2", "int0", "snap0", "5.6.7.8", 2043
        )
        self.d.add_machine(
            "name5", "name5", "1.2.3.4", "windows", ["opt3", "opt4"],
            "tag1 tag2", "int0", "snap0", "5.6.7.8", 2043, "3390", 1
        )

        m1 = self.d.view_machine("name1")
        m2 = self.d.view_machine("name2")
        m3 = self.d.view_machine("name3")
        m4 = self.d.view_machine("name4")
        m5 = self.d.view_machine("name5")
        assert m1.options == []
        assert m2.options == []
        assert m3.options == ["opt1", "opt2"]
        assert m4.options == ["opt3", "opt4"]
        assert m5.rdp_port == "3390"
        assert m5.locked_by == 1

    def test_lock_machine(self):
        self.d.add_machine(
            "doge1", "doge1", "1.2.3.4", "windows", "opt1 opt2",
            "tag1 tag2", "int0", "snap0", "5.6.7.8", 2043
        )
        self.d.add_machine(
            "doge2", "doge2", "1.2.3.4", "DogeOS", ["opt3", "opt4"],
            "tag1 tag2", "int0", "snap0", "5.6.7.8", 2043
        )
        self.d.add_machine(
            "doge3", "doge3", "1.2.3.4", "DogeOSv2", ["opt3", "opt4"],
            "tag3", "int0", "snap0", "5.6.7.8", 2043
        )
        self.d.add_machine(
            "doge4", "doge4", "1.2.3.4", "CuckooOS", ["opt3", "opt4"],
            "tag1", "int0", "snap0", "5.6.7.8", 2043
        )

        m1 = self.d.lock_machine(label="doge1")
        m2 = self.d.lock_machine(platform="DogeOS")
        m3 = self.d.lock_machine(tags=["tag3"])
        m4 = self.d.lock_machine(label="doge4", locked_by=42)
        m5 = self.d.lock_machine(locked_by=42)

        assert m1.label == "doge1" and m1.locked_by is None and m1.locked
        assert m2.platform == "DogeOS" and m2.locked_by is None and m2.locked
        assert m3.label == "doge3" and m3.locked_by is None and m3.locked
        assert m4.label == "doge4" and m4.locked_by == 42 and m4.locked
        assert m5.label == "doge4" and m5.locked_by == 42 and m5.locked

    def test_count_machines_available(self):

        count = self.d.count_machines_available()
        self.d.add_machine(
            "count_machines1", "count_machines1", "1.2.3.4", "windows",
            "opt1 opt2", "tag1 tag2", "int0", "snap0", "5.6.7.8", 2043
        )
        self.d.add_machine(
            "count_machines2", "count_machines2", "1.2.3.4", "DogeOS",
            ["opt3", "opt4"], "tag1 tag2", "int0", "snap0", "5.6.7.8", 2043
        )

        self.d.lock_machine(locked_by=4242)

        r1 = self.d.count_machines_available()
        r2 = self.d.count_machines_available(locked_by=4242)

        assert r1 == count + 1
        assert r2 == count + 2

    def test_exp_lock_machine(self):
        self.d.add_machine(
            "exp_lock_machine1", "exp_lock_machine1", "1.2.3.4", "windows", "opt1 opt2",
            "tag1 tag2", "int0", "snap0", "5.6.7.8", 2043
        )

        task_id = self.d.add_path(self.create_file(), experiment=True,
                                  name="exp_lock_machine", runs=78,
                                  delta="19d")
        task = self.d.view_task(task_id)
        self.d.lock_machine(locked_by=task.experiment_id,
                            label="exp_lock_machine1")
        exp = self.d.view_experiment(id=task.experiment_id)

        assert exp.machine_name == "exp_lock_machine1"

    def test_count_experiments(self):

        ses = self.d.Session()

        q = ses.query(Experiment)
        count = q.count()
        count_u = q.filter(Experiment.machine_name == None).filter(
            Experiment.runs != 0
        ).count()
        count_pro = q.filter(Experiment.machine_name != None).filter(
            Experiment.runs != 0
        ).count()
        count_fin = q.filter_by(runs=0).count()

        self.d.add_path(self.create_file(), experiment=True,
                                  name="test_count1", runs=3, delta="1s")
        self.d.add_path(self.create_file(), experiment=True,
                          name="test_count2", runs=0, delta="2s")
        task_id = self.d.add_path(self.create_file(), experiment=True,
                          name="test_count3", runs=3, delta="3s")

        self.d.add_machine(
            "test_count1", "test_count", "1.2.3.4", "windows", "opt1 opt2",
            "tag1 tag2", "int0", "snap0", "5.6.7.8", 2043
        )
        task = self.d.view_task(task_id)
        self.d.lock_machine(label="test_count", locked_by=task.experiment_id)

        assert (count + 3) == self.d.count_experiments()
        assert (count_u + 1) ==  self.d.count_experiments(status="unassigned")
        assert (count_pro + 1) == self.d.count_experiments(status="processing")
        assert (count_fin + 1) == self.d.count_experiments(status="finished")

    def test_unlock_machine(self):
        self.d.add_machine(
            "locknormal", "locknormal", "1.2.3.4", "CuckooOS", ["opt3", "opt4"],
            "tag1", "int0", "snap0", "5.6.7.8", 2043
        )
        self.d.add_machine(
            "lockexp", "lockexp", "1.2.3.4", "CuckooOS", ["opt3", "opt4"],
            "tag1", "int0", "snap0", "5.6.7.8", 2043
        )
        m_norm_l = self.d.lock_machine(label="locknormal")
        m_exp_l = self.d.lock_machine(label="lockexp", locked_by=1337)

        m_norm_u = self.d.unlock_machine("locknormal")
        m_exp_u = self.d.unlock_machine(locked_by=1337)

        assert m_norm_l.locked
        assert m_exp_l.locked and m_exp_l.locked_by == 1337
        assert not m_norm_u.locked and m_norm_u.label == m_norm_l.label
        assert not m_exp_u.locked and m_exp_u.label == m_exp_l.label
        assert m_exp_u.locked_by is None

    def test_unlock_machine_by_experiment(self):
        self.d.add_machine(
            "unlock_by_exp1", "unlock_by_exp1", "1.2.3.4", "CuckooOS", ["opt3", "opt4"],
            "tag1", "int0", "snap0", "5.6.7.8", 2043, locked_by=100
        )

        machine = self.d.view_machine("unlock_by_exp1")
        machine_unlocked = self.d.unlock_machine_by_experiment(100)
        machine_none = self.d.unlock_machine_by_experiment(8274782)

        assert machine.locked_by == 100
        assert machine_unlocked.locked_by is None
        assert machine_none is None

    def test_schedule_task_exp(self):
        task_id = self.d.add_path(self.create_file(), experiment=True,
                                  name="test_schedule", runs=2,
                                  delta="1d10h", timeout=1200)

        task_u = self.d.view_task(task_id)
        task_s = self.d.schedule_task_exp(task_id, timeout=821)
        task = self.d.view_task(task_s.id)

        assert task.timeout == 821
        assert task.status == "pending"
        assert (task.added_on - datetime.datetime.now()).days == 1
        assert task.experiment.runs == 1
        assert task.experiment.times == 1

    def test_list_experiments(self):

        exp_list = self.d.list_experiments()
        for x in range(1, 3):
            self.d.add_path(self.create_file(), experiment=True,
                            name="list_exp%s" % x, runs=3, delta="2h")

        assert len(exp_list) + 2 == len(self.d.list_experiments())
        assert len([
                   s for s in self.d.list_experiments()
                   if s.name in ["list_exp1", "list_exp2"]
                   ]) == 2
        assert exp_list.pop().last_task is not None


    @mock.patch("cuckoo.common.objects.magic")
    def test_add_sample(self, p):
        p.from_file.return_value = ""
        assert self.d.add_path(Files.temp_put(os.urandom(16))) is not None

class TestConnectOnce(object):
    def setup(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()
        index_yara()

    @mock.patch("cuckoo.main.Database")
    @mock.patch("cuckoo.apps.apps.Database")
    @mock.patch("cuckoo.apps.apps.process")
    def test_process_task(self, q, p1, p2):
        mkdir(cwd(analysis=1))
        p1.return_value.view_task.return_value = {}
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

    def test_long_options_custom(self):
        task_id = self.d.add_url(
            "http://google.com/", options="A"*1024, custom="B"*1024
        )
        task = self.d.view_task(task_id)
        assert task._options == "A"*1024
        assert task.custom == "B"*1024

    def test_empty_submit_id(self):
        task_id = self.d.add_url("http://google.com/")
        task = self.d.view_task(task_id)
        assert task.submit_id is None

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

    def test_task_options_custom(cls):
        tasks = cls.d.engine.execute(
            "SELECT options, custom FROM tasks WHERE id = 1"
        ).fetchall()
        assert tasks[0][0] == "human=1"
        assert tasks[0][1] == "custom1"

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

@pytest.mark.skipif("sys.platform != 'linux2'")
class DistributedDatabaseEngine(object):
    URI = None

    @classmethod
    def setup_class(cls):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()

        # Don't judge me!
        with open(cwd("distributed", "settings.py"), "a+b") as f:
            f.write("\nSQLALCHEMY_DATABASE_URI = %r\n" % cls.URI)

        cls.app = create_app()

    def test_dummy(self):
        pass

class TestDistributedSqlite3Memory(DistributedDatabaseEngine):
    URI = "sqlite:///:memory:"

class TestDistributedSqlite3File(DistributedDatabaseEngine):
    URI = "sqlite:///%s" % tempfile.mktemp()

class TestDistributedPostgreSQL(DistributedDatabaseEngine):
    URI = "postgresql://cuckoo:cuckoo@localhost/distcuckootest"

class TestDistributedMySQL(DistributedDatabaseEngine):
    URI = "mysql://cuckoo:cuckoo@localhost/distcuckootest"
