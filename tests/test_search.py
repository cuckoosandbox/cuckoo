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

def do_search(report1, report2, term, value):
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
    t = get_dummy_task(report1['info']['id'])
    session.add(t)
    report = report1
    mongo.db.analysis.save(report)
    ## Inserting 2nd report
    t = get_dummy_task(report2['info']['id'])
    session.add(t)
    report = report2
    mongo.db.analysis.save(report)

    ## Commit the changes
    session.commit()

    result = searcher.find(term, value)

    assert len(result) == 1
    assert result[0]['id'] == report1['info']['id']

def test_mongo_file_name():
    report1 = {'target':
                  {'file':
                       {'name': 'test1'}
                   },
              'info':
                  {'id':1000,
                   'category':'url'}
              }

    report2 = {'target':
                  {'file':
                       {'name': 'test2'}
                   },
              'info':
                  {'id': 1001,
                   'category':'url'}
              }

    do_search(report1, report2, "name", report1['target']['file']['name'])
    do_search(report2, report1, "name", report2['target']['file']['name'])

def test_mongo_file_type():
    report1 = {'target':
                  {'file':
                       {'type': 'test1'}
                   },
              'info':
                  {'id':1000,
                   'category':'url'}
              }

    report2 = {'target':
                  {'file':
                       {'type': 'test2'}
                   },
              'info':
                  {'id': 1001,
                   'category':'url'}
              }

    do_search(report1, report2, "type", report1['target']['file']['type'])
    do_search(report2, report1, "type", report2['target']['file']['type'])

def test_mongo_string():
    report1 = {'strings': ["test1"],
              'info':
                  {'id':1000,
                   'category':'url'}
              }

    report2 = {'strings': ["test2"],
              'info':
                  {'id': 1001,
                   'category':'url'}
              }

    do_search(report1, report2, "string", report1['strings'][0])
    do_search(report2, report1, "string", report2['strings'][0])

def test_mongo_file_ssdeep():
    report1 = {'target':
                  {'file':
                       {'ssdeep': 'test1'}
                   },
              'info':
                  {'id':1000,
                   'category':'url'}
              }

    report2 = {'target':
                  {'file':
                       {'ssdeep': 'test2'}
                   },
              'info':
                  {'id': 1001,
                   'category':'url'}
              }

    do_search(report1, report2, "ssdeep", report1['target']['file']['ssdeep'])
    do_search(report2, report1, "ssdeep", report2['target']['file']['ssdeep'])

def test_mongo_file_crc32():
    report1 = {'target':
                  {'file':
                       {'crc32': 'test1'}
                   },
              'info':
                  {'id':1000,
                   'category':'url'}
              }

    report2 = {'target':
                  {'file':
                       {'crc32': 'test2'}
                   },
              'info':
                  {'id': 1001,
                   'category':'url'}
              }

    do_search(report1, report2, "crc32", report1['target']['file']['crc32'])
    do_search(report2, report1, "crc32", report2['target']['file']['crc32'])

def test_mongo_file_md5():
    report1 = {'target':
                  {'file':
                       {'md5': 'f898ee36a6ac4a1cb6aa9a2d1fa73442'}
                   },
              'info':
                  {'id':1000,
                   'category':'url'}
              }

    report2 = {'target':
                  {'file':
                       {'md5': 'f898ee36a6ac4a1cb6aa9a2d1fa73443'}
                   },
              'info':
                  {'id': 1001,
                   'category':'url'}
              }

    do_search(report1, report2, "md5", report1['target']['file']['md5'])
    do_search(report2, report1, "md5", report2['target']['file']['md5'])

def test_mongo_file_sha1():
    report1 = {'target':
                  {'file':
                       {'sha1': '48b4f7e5bdad1aec04a70c946f734903c4adda55'}
                   },
              'info':
                  {'id':1000,
                   'category':'url'}
              }

    report2 = {'target':
                  {'file':
                       {'sha1': '48b4f7e5bdad1aec04a70c946f734903c4adda56'}
                   },
              'info':
                  {'id': 1001,
                   'category':'url'}
              }

    do_search(report1, report2, "sha1", report1['target']['file']['sha1'])
    do_search(report2, report1, "sha1", report2['target']['file']['sha1'])

def test_mongo_file_sha256():
    report1 = {'target':
                  {'file':
                       {'sha256': 'c4a5315735b53291e5ef75c263519507c5a6521f405b47bcf41c0ace6d3e8ec5'}
                   },
              'info':
                  {'id':1000,
                   'category':'url'}
              }

    report2 = {'target':
                  {'file':
                       {'sha256': 'c4a5315735b53291e5ef75c263519507c5a6521f405b47bcf41c0ace6d3e8ec6'}
                   },
              'info':
                  {'id': 1001,
                   'category':'url'}
              }

    do_search(report1, report2, "sha256", report1['target']['file']['sha256'])
    do_search(report2, report1, "sha256", report2['target']['file']['sha256'])

def test_mongo_file_sha512():
    report1 = {'target':
                  {'file':
                       {'sha512': '9782158e5a014c110fe0b9a269f1fd2a595b6c44b2786d70c0e424992ae54ef68bd23e631da5b4b3be56e93f3d583b7b2b0807ff1212b141b76ff48b534c7df1'}
                   },
              'info':
                  {'id':1000,
                   'category':'url'}
              }

    report2 = {'target':
                  {'file':
                       {'sha512': '9782158e5a014c110fe0b9a269f1fd2a595b6c44b2786d70c0e424992ae54ef68bd23e631da5b4b3be56e93f3d583b7b2b0807ff1212b141b76ff48b534c7df2'}
                   },
              'info':
                  {'id': 1001,
                   'category':'url'}
              }

    do_search(report1, report2, "sha512", report1['target']['file']['sha512'])
    do_search(report2, report1, "sha512", report2['target']['file']['sha512'])

def test_mongo_file():
    report1 = {'behavior':
                  {'summary':
                       {'files': ['test1']}
                   },
              'info':
                  {'id':1000,
                   'category':'url'}
              }

    report2 = {'behavior':
                  {'summary':
                       {'files': ['test2']}
                   },
              'info':
                  {'id': 1001,
                   'category':'url'}
              }

    do_search(report1, report2, "file", report1['behavior']['summary']['files'][0])
    do_search(report2, report1, "file", report2['behavior']['summary']['files'][0])

def test_mongo_key():
    report1 = {'behavior':
                  {'summary':
                       {'keys': ['test1']}
                   },
              'info':
                  {'id':1000,
                   'category':'url'}
              }

    report2 = {'behavior':
                  {'summary':
                       {'keys': ['test2']}
                   },
              'info':
                  {'id': 1001,
                   'category':'url'}
              }

    do_search(report1, report2, "key", report1['behavior']['summary']['keys'][0])
    do_search(report2, report1, "key", report2['behavior']['summary']['keys'][0])

def test_mongo_mutex():
    report1 = {'behavior':
                  {'summary':
                       {'mutex': ['test1']}
                   },
              'info':
                  {'id':1000,
                   'category':'url'}
              }

    report2 = {'behavior':
                  {'summary':
                       {'mutex': ['test2']}
                   },
              'info':
                  {'id': 1001,
                   'category':'url'}
              }

    do_search(report1, report2, "mutex", report1['behavior']['summary']['mutex'][0])
    do_search(report2, report1, "mutex", report2['behavior']['summary']['mutex'][0])

def test_mongo_domain():
    report1 = {'network':
                  {'domains': [{'domain': 'test1'}]
                   },
              'info':
                  {'id':1000,
                   'category':'url'}
              }

    report2 = {'network':
                   {'domains': [{'domain': 'test2'}]
                    },
               'info':
                   {'id': 1001,
                    'category': 'url'}
               }

    do_search(report1, report2, "domain", report1['network']['domains'][0]['domain'])
    do_search(report2, report1, "domain", report2['network']['domains'][0]['domain'])

def test_mongo_ip():
    report1 = {'network':
                  {'hosts': 'test1'},
              'info':
                  {'id':1000,
                   'category':'url'}
              }

    report2 = {'network':
                   {'hosts': 'test2'},
               'info':
                   {'id': 1001,
                    'category': 'url'}
               }

    do_search(report1, report2, "ip", report1['network']['hosts'])
    do_search(report2, report1, "ip", report2['network']['hosts'])

def test_mongo_imphash():
    report1 = {'static':
                  {'pe_imphash': 'test1'},
              'info':
                  {'id':1000,
                   'category':'url'}
              }

    report2 = {'static':
                   {'pe_imphash': 'test2'},
               'info':
                   {'id': 1001,
                    'category': 'url'}
               }

    do_search(report1, report2, "imphash", report1['static']['pe_imphash'])
    do_search(report2, report1, "imphash", report2['static']['pe_imphash'])

def test_mongo_signature():
    report1 = {'signatures':
                  [{'families': ['test1_family'],
                   'name': 'test1',
                   'marks':
                       [{'call':
                            {'api': 'test1_api'}
                        }],
                   'description': 'test1_desc'
                   }],
              'info':
                  {'id':1000,
                   'category':'url'}
              }

    report2 = {'signatures':
                   [{'families': ['test2_family'],
                     'name': 'test2',
                     'marks':
                         [{'call':
                               {'api': 'test2_api'}
                           }],
                     'description': 'test2_desc'
                     }],
               'info':
                   {'id': 1001,
                    'category': 'url'}
               }

    ## Search for family
    do_search(report1, report2, "signature", report1['signatures'][0]['families'][0])
    do_search(report2, report1, "signature", report2['signatures'][0]['families'][0])

    ## Search for name
    do_search(report1, report2, "signature", report1['signatures'][0]['name'])
    do_search(report2, report1, "signature", report2['signatures'][0]['name'])

    ## Search for api
    do_search(report1, report2, "signature", report1['signatures'][0]['marks'][0]['call']['api'])
    do_search(report2, report1, "signature", report2['signatures'][0]['marks'][0]['call']['api'])

    ## Search for descriptions
    do_search(report1, report2, "signature", report1['signatures'][0]['description'])
    do_search(report2, report1, "signature", report2['signatures'][0]['description'])

def test_mongo_url():
    report1 = {'target':
                  {'file':
                       {'urls': ['test1']},
                   'url': 'test1'
                   },
              'info':
                  {'id':1000,
                   'category':'url'}
              }

    report2 = {'target':
                  {'file':
                       {'urls': ['test2']},
                   'url': 'test2'
                   },
              'info':
                  {'id': 1001,
                   'category':'url'}
              }

    ## Search for file URLs
    do_search(report1, report2, "url", report1['target']['file']['urls'][0])
    do_search(report2, report1, "url", report2['target']['file']['urls'][0])

    ## Search for URL
    do_search(report1, report2, "url", report1['target']['url'])
    do_search(report2, report1, "url", report2['target']['url'])

def test_mongo_args():
    report1 = {'behavior':
                  {'processes':
                   [{'command_line': 'test1'}]},
              'info':
                  {'id':1000,
                   'category':'url'}
              }

    report2 = {'behavior':
                   {'processes':
                    [{'command_line': 'test2'}]},
               'info':
                   {'id': 1001,
                    'category': 'url'}
               }

    ## Search for command line arguments
    do_search(report1, report2, "args", report1['behavior']['processes'][0]['command_line'])
    do_search(report2, report1, "args", report2['behavior']['processes'][0]['command_line'])

def test_mongo_regkey_read():
    report1 = {'behavior':
                  {'summary':
                   {'regkey_read': ['test1']}},
              'info':
                  {'id':1000,
                   'category':'url'}
              }

    report2 = {'behavior':
                   {'summary':
                    {'regkey_read': ['test2']}},
               'info':
                   {'id': 1001,
                    'category': 'url'}
               }

    ## Search for command line arguments
    do_search(report1, report2, "regkey_read", report1['behavior']['summary']['regkey_read'][0])
    do_search(report2, report1, "regkey_read", report2['behavior']['summary']['regkey_read'][0])

def test_mongo_regkey_opened():
    report1 = {'behavior':
                  {'summary':
                   {'regkey_opened': ['test1']}},
              'info':
                  {'id':1000,
                   'category':'url'}
              }

    report2 = {'behavior':
                   {'summary':
                    {'regkey_opened': ['test2']}},
               'info':
                   {'id': 1001,
                    'category': 'url'}
               }

    ## Search for command line arguments
    do_search(report1, report2, "regkey_opened", report1['behavior']['summary']['regkey_opened'][0])
    do_search(report2, report1, "regkey_opened", report2['behavior']['summary']['regkey_opened'][0])

def test_mongo_regkey_written():
    report1 = {'behavior':
                  {'summary':
                   {'regkey_written': ['test1']}},
              'info':
                  {'id':1000,
                   'category':'url'}
              }

    report2 = {'behavior':
                   {'summary':
                    {'regkey_written': ['test2']}},
               'info':
                   {'id': 1001,
                    'category': 'url'}
               }

    ## Search for command line arguments
    do_search(report1, report2, "regkey_written", report1['behavior']['summary']['regkey_written'][0])
    do_search(report2, report1, "regkey_written", report2['behavior']['summary']['regkey_written'][0])


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
