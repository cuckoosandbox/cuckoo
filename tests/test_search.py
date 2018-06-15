# Copyright (C) 2017-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import os
import tempfile

from cuckoo.common.elastic import Elastic
from cuckoo.common.mongo import Mongo, mongo
from cuckoo.common.objects import File
from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd
from cuckoo.reporting.mongodb import MongoDB

def test_mongo_init_nouser():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "reporting": {
            "mongodb": {
                "enabled": True,
                "host": "1.2.3.4",
                "port": 4242,
                "db": "foobar",
            },
        },
    })
    m = Mongo()
    m.init()
    assert m.enabled is True
    assert m.hostname == "1.2.3.4"
    assert m.port == 4242
    assert m.database == "foobar"
    assert m.username is None
    assert m.password is None

def test_mongo_init_withuser():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "reporting": {
            "mongodb": {
                "enabled": True,
                "username": "foo",
                "password": "bar",
            },
        },
    })
    m = Mongo()
    m.init()
    assert m.enabled is True
    assert m.hostname == "127.0.0.1"
    assert m.port == 27017
    assert m.database == "cuckoo"
    assert m.username == "foo"
    assert m.password == "bar"

@mock.patch("cuckoo.common.mongo.pymongo")
def test_mongo_connect_notenabled(p):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    m = Mongo()
    m.init()
    m.connect()
    p.MongoClient.assert_not_called()

@mock.patch("cuckoo.common.mongo.gridfs")
@mock.patch("cuckoo.common.mongo.pymongo")
def test_mongo_connect_success_nouser(p, q):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "reporting": {
            "mongodb": {
                "enabled": True,
            },
        },
    })
    m = Mongo()
    m.init()
    m.connect()
    p.MongoClient.assert_called_once_with("127.0.0.1", 27017)
    client = p.MongoClient.return_value
    client.__getitem__.assert_called_once_with("cuckoo")
    db = client.__getitem__.return_value
    db.authenticate.assert_not_called()
    q.GridFS.assert_called_once_with(db)
    assert m.db == db
    assert m.grid == q.GridFS.return_value

@mock.patch("cuckoo.common.mongo.gridfs")
@mock.patch("cuckoo.common.mongo.pymongo")
def test_mongo_connect_success_withuser(p, q):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "reporting": {
            "mongodb": {
                "enabled": True,
                "username": "foo",
                "password": "bar",
            },
        },
    })
    m = Mongo()
    m.init()
    m.connect()
    db = p.MongoClient.return_value.__getitem__.return_value
    db.authenticate.assert_called_once_with("foo", "bar")

def test_mongo_connect_store_file():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "reporting": {
            "mongodb": {
                "enabled": True,
                "db": "cuckootest",
            },
        },
    })

    mongo.init()
    assert mongo.database == "cuckootest"

    fd, filepath = tempfile.mkstemp()
    os.write(fd, "hello world")
    os.close(fd)
    f = File(filepath)

    r = MongoDB()
    r.init_once()
    id1 = r.store_file(f, "foobar.txt")
    id2 = r.store_file(f, "foobar.txt")
    assert id1 == id2

    assert mongo.db.fs.files.find_one({
        "sha256": f.get_sha256(),
    })["_id"] == id1

    assert mongo.grid.get(id1).read() == "hello world"

def test_elastic_init():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "reporting": {
            "elasticsearch": {
                "enabled": True,
                "hosts": [
                    "localhost",
                ],
                "calls": True,
            },
        },
    })
    e = Elastic()
    e.init()
    assert e.enabled is True
    assert e.hosts == ["localhost"]
    assert e.calls is True
    assert e.index == "cuckoo"
    assert e.index_time_pattern == "yearly"
    assert e.cuckoo_node is None

@mock.patch("elasticsearch.Elasticsearch")
def test_elastic_connect_notenabled(p):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "reporting": {
            "elasticsearch": {
                "enabled": False,
            },
        },
    })
    e = Elastic()
    e.init()
    e.connect()
    p.assert_not_called()

@mock.patch("elasticsearch.Elasticsearch")
def test_elastic_connect_enabled(p):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "reporting": {
            "elasticsearch": {
                "enabled": True,
            },
        },
    })
    e = Elastic()
    e.init()
    e.connect()
    p.assert_called_once_with(["127.0.0.1"], timeout=300)
