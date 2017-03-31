# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import os
import tempfile

from cuckoo.common.search import searcher
from cuckoo.common.elastic import Elastic
from cuckoo.common.mongo import Mongo, mongo
from cuckoo.common.objects import File
from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd
from cuckoo.reporting.mongodb import MongoDB
from cuckoo.core.database import Database, Task

report = {'target':
                  {'file':
                       {'name': 'c4a5315735b53291e5ef75c263519507c5a6521f405b47bcf41c0ace6d3e8ec5',
                        'type': 'PE32 executable (GUI) Intel 80386, for MS Windows',
                        'ssdeep': 'test1',
                        'crc32': '015B8A68',
                        'md5': 'f898ee36a6ac4a1cb6aa9a2d1fa73442',
                        'sha1': '48b4f7e5bdad1aec04a70c946f734903c4adda55',
                        'sha256': 'c4a5315735b53291e5ef75c263519507c5a6521f405b47bcf41c0ace6d3e8ec5',
                        'sha512': '9782158e5a014c110fe0b9a269f1fd2a595b6c44b2786d70c0e424992ae54ef68bd23e631da5b4b3be56e93f3d583b7b2b0807ff1212b141b76ff48b534c7df1',
                        'urls': ['http://ns.adobe.com/xap/1.0/sType/ResourceEvent'],
                        }
                   },
          'behavior':
                  {'summary':
                       {'files': ['C:\Users\Administrator\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.MSO\94986FA4.gif'],
                        'keys': ['test1'],
                        'mutex': ['Global\{754E1424-2073-665E-296D-2E3CE0A0FF4B}'],
                        'regkey_read': ['HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\explorer\FolderDescriptions\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}\Security'],
                        'regkey_opened': ['HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\explorer\FolderDescriptions\{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\PropertyBag'],
                        'regkey_written': ['HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Tracing\powershell_RASMANCS\FileDirectory'],
                        },
                   'processes': [{'command_line': 'C:\Windows\system32\lsass.exe'}],
                   },
          'network':
                  {'domains': [{'domain': 'teredo.ipv6.microsoft.com'}],
                   'hosts': '8.8.8.8',
                   },
          'static':
                  {'pe_imphash': '7e96272130a52e872e7657f7decf2886'},
          'signatures':
                  [{'families': ['test1_family'],
                    'name': 'antivm_memory_available',
                    'marks':
                        [{'call':
                            {'api': 'GlobalMemoryStatusEx'}
                          }],
                    'description': 'Checks amount of memory in system, this can be used to detect virtual machines that have a low amount of memory available'
                    }],

          'strings': ["test1"],
          'info':
                  {'id':1000,
                   'category':'url'},
          }

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

def get_dummy_task(id):
    t = Task(id=id)
    t.target = ""
    t.category = ""
    t.timeout = ""
    t.package = ""
    t.options = ""
    t.priority = 0
    t.custom = ""
    t.owner = ""
    t.machine = ""
    t.platform = ""
    t.submit_id = id
    return t

def do_search(term, value):
    global report
    ## create temp CWD
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "reporting": {
            "mongodb": {
                "enabled": True,
                "db": "cuckootest",
            },
        },
    })

    ## Setup MongoDB
    mongo.init()
    assert mongo.database == "cuckootest"
    mongo.drop()
    mongo.connect()

    ## Setup Database
    db = Database()
    db.connect()
    session = db.Session()

    ## Inserting 1st report
    t = get_dummy_task(report['info']['id'])
    session.add(t)
    mongo.db.analysis.save(report)

    ## Commit the changes
    session.commit()

    result = searcher.find(term, value)

    assert len(result) == 1
    assert result[0]['id'] == report['info']['id']

def test_mongo_search():
    do_search("name", report['target']['file']['name'])
    do_search("type", report['target']['file']['type'])
    do_search("string", report['strings'][0])
    do_search("ssdeep", report['target']['file']['ssdeep'])
    do_search("crc32", report['target']['file']['crc32'])
    do_search(None, report['target']['file']['crc32'])
    do_search("md5", report['target']['file']['md5'])
    do_search(None, report['target']['file']['md5'])
    do_search("sha1", report['target']['file']['sha1'])
    do_search(None, report['target']['file']['sha1'])
    do_search("sha256", report['target']['file']['sha256'])
    do_search(None, report['target']['file']['sha256'])
    do_search("sha512", report['target']['file']['sha512'])
    do_search(None, report['target']['file']['sha512'])
    do_search("file", report['behavior']['summary']['files'][0])
    do_search("key", report['behavior']['summary']['keys'][0])
    do_search("mutex", report['behavior']['summary']['mutex'][0])
    do_search("domain", report['network']['domains'][0]['domain'])
    do_search("ip", report['network']['hosts'])
    do_search(None, report['network']['hosts'])
    do_search("imphash", report['static']['pe_imphash'])
    do_search("signature", report['signatures'][0]['families'][0])
    do_search("signature", report['signatures'][0]['name'])
    do_search("signature", report['signatures'][0]['marks'][0]['call']['api'])
    do_search("signature", report['signatures'][0]['description'])
    do_search("url", report['target']['file']['urls'][0])
    do_search(None, report['target']['file']['urls'][0])
    do_search("args", report['behavior']['processes'][0]['command_line'])
    do_search("regkey_read", report['behavior']['summary']['regkey_read'][0])
    do_search("regkey_opened", report['behavior']['summary']['regkey_opened'][0])
    do_search("regkey_written", report['behavior']['summary']['regkey_written'][0])


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

@mock.patch("cuckoo.common.elastic.elasticsearch")
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
    p.Elasticsearch.assert_not_called()

@mock.patch("cuckoo.common.elastic.elasticsearch")
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
    p.Elasticsearch.assert_called_once_with(["127.0.0.1"])
