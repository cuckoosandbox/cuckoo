# Copyright (C) 2016-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import mock
import os
import pytest
import shutil
import tempfile

from cuckoo.apps.import_ import (
    identify, import_legacy_analyses, dumpcmd, movesql, sqldump
)
from cuckoo.common.config import config
from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.common.files import Files, temppath
from cuckoo.core.database import Database
from cuckoo.main import cuckoo_create, main
from cuckoo.misc import cwd, set_cwd, mkdir, is_windows, is_linux, is_macosx

log = logging.getLogger(__name__)

constants_04_py = """
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

CUCKOO_ROOT = os.path.normpath(os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "..", ".."))
CUCKOO_VERSION = "0.4"
CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004
"""

constants_041_py = """
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

CUCKOO_ROOT = os.path.normpath(os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "..", ".."))
CUCKOO_VERSION = "0.4.1"
CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004
"""

constants_042_py = """
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

CUCKOO_ROOT = os.path.normpath(os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "..", ".."))
CUCKOO_VERSION = "0.4.2"
CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004
"""

constants_05_py = """
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

CUCKOO_ROOT = os.path.normpath(os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "..", ".."))
CUCKOO_VERSION = "0.5"
CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004
"""

constants_06_py = """
# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

CUCKOO_ROOT = os.path.normpath(os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "..", ".."))
CUCKOO_VERSION = "0.6"
CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004
"""

constants_10_py = """
# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os


_current_dir = os.path.abspath(os.path.dirname(__file__))
CUCKOO_ROOT = os.path.normpath(os.path.join(_current_dir, "..", "..", ".."))

CUCKOO_VERSION = "1.0"
CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004
"""

constants_11_py = """
# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os


_current_dir = os.path.abspath(os.path.dirname(__file__))
CUCKOO_ROOT = os.path.normpath(os.path.join(_current_dir, "..", "..", ".."))

CUCKOO_VERSION = "1.1"
CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004
"""

constants_12_py = """
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

_current_dir = os.path.abspath(os.path.dirname(__file__))
CUCKOO_ROOT = os.path.normpath(os.path.join(_current_dir, "..", "..", ".."))

CUCKOO_VERSION = "1.2"
CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004
"""

constants_20rc1_py = """
# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

_current_dir = os.path.abspath(os.path.dirname(__file__))
CUCKOO_ROOT = os.path.normpath(os.path.join(_current_dir, "..", "..", ".."))

CUCKOO_VERSION = "2.0-rc1"
CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004
"""

constants_20rc2_py = """
# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

_current_dir = os.path.abspath(os.path.dirname(__file__))
CUCKOO_ROOT = os.path.normpath(os.path.join(_current_dir, "..", "..", ".."))

CUCKOO_VERSION = "2.0-rc2"
CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004
"""

constants_20dev_py = """
# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

_current_dir = os.path.abspath(os.path.dirname(__file__))
CUCKOO_ROOT = os.path.normpath(os.path.join(_current_dir, "..", "..", ".."))

CUCKOO_VERSION = "2.0-dev"
CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004
"""

def drop_constants_py(content):
    dirpath = tempfile.mkdtemp()
    dirpath2 = os.path.join(dirpath, "lib", "cuckoo", "common")
    os.makedirs(dirpath2)
    filepath = os.path.join(dirpath2, "constants.py")
    open(filepath, "wb").write(content)
    return dirpath

def test_identify():
    dirpath = drop_constants_py(constants_04_py)
    assert identify(dirpath) == "0.4"

    dirpath = drop_constants_py(constants_041_py)
    assert identify(dirpath) == "0.4.1"

    dirpath = drop_constants_py(constants_042_py)
    assert identify(dirpath) == "0.4.2"

    dirpath = drop_constants_py(constants_05_py)
    assert identify(dirpath) == "0.5"

    dirpath = drop_constants_py(constants_06_py)
    assert identify(dirpath) == "0.6"

    dirpath = drop_constants_py(constants_10_py)
    assert identify(dirpath) == "1.0"

    dirpath = drop_constants_py(constants_11_py)
    assert identify(dirpath) == "1.1"

    dirpath = drop_constants_py(constants_12_py)
    assert identify(dirpath) == "1.2"

    dirpath = drop_constants_py(constants_20rc1_py)
    assert identify(dirpath) == "2.0-rc1"

    dirpath = drop_constants_py(constants_20rc2_py)
    assert identify(dirpath) == "2.0-rc2"

    dirpath = drop_constants_py(constants_20dev_py)
    assert identify(dirpath) == "2.0-dev"

    dirpath = drop_constants_py("hello world")
    assert identify(dirpath) is None

def init_legacy_analyses():
    dirpath = tempfile.mkdtemp()
    mkdir(dirpath, "storage")
    mkdir(dirpath, "storage", "analyses")

    mkdir(dirpath, "storage", "analyses", "1")
    mkdir(dirpath, "storage", "analyses", "1", "logs")
    Files.create(
        (dirpath, "storage", "analyses", "1", "logs"), "a.txt", "a"
    )
    mkdir(dirpath, "storage", "analyses", "1", "reports")
    Files.create(
        (dirpath, "storage", "analyses", "1", "reports"), "b.txt", "b"
    )

    mkdir(dirpath, "storage", "analyses", "2")
    Files.create((dirpath, "storage", "analyses", "2"), "cuckoo.log", "log")

    if not is_windows():
        os.symlink(
            "thisisnotanexistingfile",
            os.path.join(dirpath, "storage", "analyses", "2", "binary")
        )

    Files.create((dirpath, "storage", "analyses"), "latest", "last!!1")
    return dirpath

def init_import_legacy(mode):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    dirpath = init_legacy_analyses()
    assert sorted(import_legacy_analyses(mode, dirpath)) == [1, 2]
    assert open(cwd("logs", "a.txt", analysis=1), "rb").read() == "a"
    assert open(cwd("reports", "b.txt", analysis=1), "rb").read() == "b"
    assert open(cwd("cuckoo.log", analysis=2), "rb").read() == "log"
    assert not os.path.exists(cwd(analysis="latest"))
    return dirpath

def test_import_cuckoo_cwd(capsys):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    with pytest.raises(SystemExit):
        main.main(
            ("--cwd", cwd(), "import", cwd()), standalone_mode=False
        )

    out, _ = capsys.readouterr()
    assert "import a legacy Cuckoo" in out

def test_import_legacy_analyses_copy():
    dirpath = init_import_legacy("copy")

    dirpath1 = os.path.join(dirpath, "storage", "analyses", "1")
    assert os.path.isdir(dirpath1)
    filepath = os.path.join(dirpath1, "logs", "a.txt")
    assert open(filepath, "rb").read() == "a"

    dirpath2 = os.path.join(dirpath, "storage", "analyses", "2")
    assert os.path.isdir(dirpath2)

    assert os.path.isdir(cwd(analysis=1))
    assert os.path.isdir(cwd(analysis=2))

def test_import_legacy_analyses_move():
    dirpath = init_import_legacy("move")

    dirpath1 = os.path.join(dirpath, "storage", "analyses", "1")
    assert not os.path.isdir(dirpath1)

    dirpath2 = os.path.join(dirpath, "storage", "analyses", "2")
    assert not os.path.isdir(dirpath2)

    assert os.path.isdir(cwd(analysis=1))
    assert os.path.isdir(cwd(analysis=2))

if not is_windows():
    def test_import_legacy_analyses_symlink():
        dirpath = init_import_legacy("symlink")

        assert os.path.islink(cwd(analysis=1))
        assert os.path.islink(cwd(analysis=2))

        dirpath1 = os.path.join(dirpath, "storage", "analyses", "1")
        assert os.path.isdir(dirpath1)
        filepath = os.path.join(dirpath1, "logs", "a.txt")
        assert open(filepath, "rb").read() == "a"

        assert os.readlink(cwd(analysis=1)) == dirpath1

        dirpath2 = os.path.join(dirpath, "storage", "analyses", "2")
        assert os.path.isdir(dirpath2)
        assert os.readlink(cwd(analysis=2)) == dirpath2

def test_dumpcmd():
    assert dumpcmd(None, "/tmp") == (
        ["sqlite3", os.path.join("/tmp", "db/cuckoo.db"), ".dump"], {}
    )
    assert dumpcmd("sqlite:///db/cuckoo.db", "/tmp") == (
        ["sqlite3", os.path.join("/tmp", "db/cuckoo.db"), ".dump"], {}
    )
    assert dumpcmd("sqlite:////tmp/cuckoo.db", "/tmp") == (
        ["sqlite3", "/tmp/cuckoo.db", ".dump"], {}
    )
    if not is_macosx():
        assert dumpcmd("mysql://foo:bar@localh0st/baz", "/tmp") == (
            ["mysqldump", "-u", "foo", "-pbar", "-h", "localh0st", "baz"], {}
        )
        assert dumpcmd("mysql://cuckoo:random!@localhost/cuckoo", "/tmp") == (
            ["mysqldump", "-u", "cuckoo", "-prandom!", "cuckoo"], {}
        )
    if not is_macosx():
        assert dumpcmd("postgresql://user:bar@localhost/baz", "/tmp") == (
            ["pg_dump", "-U", "user", "baz"], {"PGPASSWORD": "bar"}
        )
        assert dumpcmd("postgresql://u n!:bar@localhost/baz", "/tmp") == (
            ["pg_dump", "-U", "u n!", "baz"], {"PGPASSWORD": "bar"}
        )
        assert dumpcmd("postgresql://:b@c/d", "/tmp") == (
            ["pg_dump", "-h", "c", "d"], {"PGPASSWORD": "b"}
        )

    with pytest.raises(CuckooOperationalError) as e:
        dumpcmd("notadatabaseuri", "/tmp")
    e.match("URI wasn't understood")

    with pytest.raises(CuckooOperationalError) as e:
        dumpcmd("notadatabase://a:b@c/d", "/tmp")
    e.match("URI wasn't understood")

class TestMoveSQL(object):
    def setup(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()

    @pytest.mark.skipif("sys.platform == 'darwin'")
    def test_mysql(self):
        movesql("mysql://foo:bar@localh0st/baz", None, None)

    @pytest.mark.skipif("sys.platform == 'darwin'")
    def test_postgresql(self):
        movesql("postgresql://user:bar@localhost/baz", None, None)

    def test_empty_copy(self):
        oldfilepath = Files.temp_put("hello")
        movesql("sqlite:///%s" % oldfilepath, "copy", temppath())
        assert os.path.exists(oldfilepath)
        assert os.path.exists(cwd("cuckoo.db"))
        assert not os.path.islink(cwd("cuckoo.db"))
        assert open(cwd("cuckoo.db"), "rb").read() == "hello"

    def test_empty_move(self):
        oldfilepath = Files.temp_put("hello")
        movesql("sqlite:///%s" % oldfilepath, "move", temppath())
        assert not os.path.exists(oldfilepath)
        assert os.path.exists(cwd("cuckoo.db"))
        assert not os.path.islink(cwd("cuckoo.db"))
        assert open(cwd("cuckoo.db"), "rb").read() == "hello"

    def test_empty_symlink(self):
        oldfilepath = Files.temp_put("hello")
        try:
            movesql("sqlite:///%s" % oldfilepath, "symlink", temppath())

            # Following is non-windows.
            assert os.path.exists(oldfilepath)
            assert os.path.exists(cwd("cuckoo.db"))
            assert os.path.islink(cwd("cuckoo.db"))
            assert open(cwd("cuckoo.db"), "rb").read() == "hello"
        except RuntimeError as e:
            assert is_windows()
            assert "'symlink'" in e.message

@mock.patch("cuckoo.apps.import_.subprocess")
@mock.patch("click.confirm")
def test_sqldump_noconfirm(p, q):
    p.return_value = False
    sqldump(None, "/tmp")
    q.check_call.assert_not_called()

class ImportCuckoo(object):
    @mock.patch("click.confirm")
    def test_sqldump(self, p):
        set_cwd(tempfile.mkdtemp())
        p.return_value = True

        try:
            sqldump(self.URI, "/tmp")
            assert os.path.getsize(cwd("backup.sql"))
        except CuckooOperationalError as e:
            assert "SQL database dump as the command" in e.message
            assert not is_linux()

    @mock.patch("click.confirm")
    def test_import_confirm(self, p):
        set_cwd(tempfile.mkdtemp())
        p.return_value = True

        dirpath = init_legacy_analyses()
        os.makedirs(os.path.join(dirpath, "lib", "cuckoo", "common"))
        open(os.path.join(
            dirpath, "lib", "cuckoo", "common", "constants.py"
        ), "wb").write(constants_11_py)

        shutil.copytree(
            "tests/files/conf/110_plain", os.path.join(dirpath, "conf")
        )

        filepath = os.path.join(dirpath, "conf", "cuckoo.conf")
        buf = open(filepath, "rb").read()
        open(filepath, "wb").write(buf.replace(
            "connection =", "connection = %s" % self.URI
        ))

        try:
            main.main(
                ("--cwd", cwd(), "import", dirpath), standalone_mode=False
            )
        except CuckooOperationalError as e:
            assert "SQL database dump as the command" in e.message
            assert not is_linux()
            return

        db = Database()
        db.connect()
        assert db.engine.name == self.ENGINE
        assert open(cwd("logs", "a.txt", analysis=1), "rb").read() == "a"
        assert config("cuckoo:database:connection") == self.URI
        assert db.count_tasks() == 2

    @mock.patch("click.confirm")
    def test_import_noconfirm(self, p):
        set_cwd(tempfile.mkdtemp())
        p.side_effect = True, False

        dirpath = init_legacy_analyses()
        os.makedirs(os.path.join(dirpath, "lib", "cuckoo", "common"))
        open(os.path.join(
            dirpath, "lib", "cuckoo", "common", "constants.py"
        ), "wb").write(constants_11_py)

        shutil.copytree(
            "tests/files/conf/110_plain", os.path.join(dirpath, "conf")
        )

        filepath = os.path.join(dirpath, "conf", "cuckoo.conf")
        buf = open(filepath, "rb").read()
        open(filepath, "wb").write(buf.replace(
            "connection =", "connection = %s" % self.URI
        ))

        main.main(
            ("--cwd", cwd(), "import", dirpath), standalone_mode=False
        )

        db = Database()
        db.connect()
        assert db.engine.name == self.ENGINE
        assert open(cwd("logs", "a.txt", analysis=1), "rb").read() == "a"
        assert config("cuckoo:database:connection") == self.URI
        assert db.count_tasks() == 2

class TestImportCuckooSQLite3(ImportCuckoo):
    ENGINE = "sqlite"
    _filepath = tempfile.mktemp()
    shutil.copy("tests/files/cuckoo.db", _filepath)
    URI = "sqlite:///%s" % _filepath

@pytest.mark.skipif("sys.platform == 'darwin'")
class TestImportCuckooMySQL(ImportCuckoo):
    ENGINE = "mysql"
    URI = "mysql://cuckoo:cuckoo@localhost/cuckootestimport"

@pytest.mark.skipif("sys.platform == 'darwin'")
class TestImportCuckooPostgreSQL(ImportCuckoo):
    ENGINE = "postgresql"
    URI = "postgresql://cuckoo:cuckoo@localhost/cuckootestimport"
