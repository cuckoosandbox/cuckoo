# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import tempfile

from cuckoo.common.abstracts import Machinery
from cuckoo.common.config import Config
from cuckoo.common.files import Files, Folders
from cuckoo.common.utils import Singleton
from cuckoo.core.database import Database
from cuckoo.core.resultserver import ResultServer
from cuckoo.misc import set_cwd, cwd

def test_machines():
    set_cwd(tempfile.mkdtemp())
    Folders.create(cwd(), "conf")
    Files.create(cwd("conf"), "cuckoo.conf", """
[cuckoo]
machinery = virtualbox
[database]
connection =
timeout =
[resultserver]
ip = 9.8.7.6
port = 9876
""")
    Files.create(cwd("conf"), "virtualbox.conf", """
[virtualbox]
machines = a, b, c
[a]
label = a
snapshot = derpa
platform = windows
ip = 1.2.3.4

[b]
label = b
snapshot = derpb
platform = windows
ip = 5.6.7.8
resultserver_ip = 7.5.3.1

[c]
label = c
snapshot = derpc
platform = windows
ip = 1.3.5.7
resultserver_port = 4242
""")

    class mock(object):
        port = 9001

    Singleton._instances[ResultServer] = mock()

    db = Database()
    db.connect()
    m = Machinery()
    m.set_options(Config("virtualbox"))
    m._initialize("virtualbox")

    machines = db.list_machines()
    assert len(machines) == 3
    assert machines[0].label == "a"
    assert machines[0].snapshot == "derpa"
    assert machines[0].ip == "1.2.3.4"
    assert machines[0].resultserver_ip == "9.8.7.6"
    assert machines[0].resultserver_port == 9001
    assert machines[1].label == "b"
    assert machines[1].snapshot == "derpb"
    assert machines[1].ip == "5.6.7.8"
    assert machines[1].resultserver_ip == "7.5.3.1"
    assert machines[1].resultserver_port == 9001
    assert machines[2].label == "c"
    assert machines[2].snapshot == "derpc"
    assert machines[2].ip == "1.3.5.7"
    assert machines[2].resultserver_ip == "9.8.7.6"
    assert machines[2].resultserver_port == 4242

    Singleton._instances.pop(ResultServer)
