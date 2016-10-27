# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import pytest
import shutil
import tempfile

from cuckoo.common.utils import Singleton
from cuckoo.core.init import write_supervisor_conf
from cuckoo.core.resultserver import ResultServer
from cuckoo.main import main
from cuckoo.misc import set_cwd, cwd

class TestInit(object):
    def setup(self):
        self.dirpath = tempfile.mkdtemp()
        set_cwd(self.dirpath)

    def teardown(self):
        shutil.rmtree(self.dirpath)

    def test_exists(self):
        filepath = cwd("supervisord.conf")
        open(filepath, "wb").write("foo")

        write_supervisor_conf(None)
        assert open(filepath, "rb").read() == "foo"

    def test_new(self):
        venv = os.environ.pop("VIRTUAL_ENV", None)

        write_supervisor_conf(None)
        buf = open(cwd("supervisord.conf"), "rb").read()

        assert "command = cuckoo -d -m 10000" in buf

        os.environ["VIRTUAL_ENV"] = venv

    def test_venv_new(self):
        venv = os.environ.pop("VIRTUAL_ENV", None)
        os.environ["VIRTUAL_ENV"] = self.dirpath

        write_supervisor_conf(None)
        buf = open(cwd("supervisord.conf"), "rb").read()

        cuckoo_path = "%s/bin/cuckoo" % self.dirpath
        assert "command = %s -d -m 10000" % cuckoo_path in buf

        os.environ["VIRTUAL_ENV"] = venv

    def test_cuckoo_init(self):
        """Tests that 'cuckoo init' works with a new CWD."""
        with pytest.raises(SystemExit):
            main.main(
                ("--cwd", self.dirpath, "--nolog", "init"),
                standalone_mode=False
            )

        assert os.path.exists(os.path.join(self.dirpath, "mitm.py"))

    def test_cuckoo_init_main(self):
        """Tests that 'cuckoo' works with a new CWD."""
        main.main(
            ("--cwd", self.dirpath, "--nolog"),
            standalone_mode=False
        )
        assert os.path.exists(os.path.join(self.dirpath, "mitm.py"))

    def test_cuckoo_init_no_resultserver(self):
        """Tests that 'cuckoo init' doesn't launch the ResultServer."""
        with pytest.raises(SystemExit):
            main.main(
                ("--cwd", self.dirpath, "--nolog", "init"),
                standalone_mode=False
            )

        # Raises CuckooCriticalError if ResultServer can't bind (which no
        # longer happens now, naturally).
        main.main(
            ("--cwd", self.dirpath, "--nolog", "init"),
            standalone_mode=False
        )

        assert ResultServer not in Singleton._instances
