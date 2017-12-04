# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import jinja2
import mock
import os
import pytest
import shutil
import tempfile

import cuckoo

from cuckoo.common.config import config, Config
from cuckoo.common.exceptions import CuckooConfigurationError
from cuckoo.common.files import Folders, Files
from cuckoo.common.utils import Singleton
from cuckoo.core.init import write_supervisor_conf, write_cuckoo_conf
from cuckoo.core.resultserver import ResultServer
from cuckoo.main import main, cuckoo_create
from cuckoo.misc import set_cwd, cwd, mkdir

class TestInit(object):
    def setup(self):
        set_cwd(tempfile.mkdtemp())

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

        if venv:
            os.environ["VIRTUAL_ENV"] = venv

    @pytest.mark.skipif("sys.platform != 'linux2'")
    def test_venv_new(self):
        venv = os.environ.pop("VIRTUAL_ENV", None)
        os.environ["VIRTUAL_ENV"] = cwd()

        write_supervisor_conf(None)
        buf = open(cwd("supervisord.conf"), "rb").read()

        cuckoo_path = "%s/bin/cuckoo" % cwd()
        assert "command = %s -d -m 10000" % cuckoo_path in buf

        os.environ["VIRTUAL_ENV"] = venv

    def test_venv_new_unicode(self):
        set_cwd(tempfile.mkdtemp(u"a\u202eb"))
        write_supervisor_conf(None)

    def test_cuckoo_init(self):
        """Tests that 'cuckoo init' works with a new CWD."""
        with pytest.raises(SystemExit):
            main.main(
                ("--cwd", cwd(), "--nolog", "init"),
                standalone_mode=False
            )

        assert os.path.exists(os.path.join(cwd(), "conf"))
        assert os.path.exists(os.path.join(cwd(), "log"))
        assert os.path.exists(os.path.join(cwd(), "pidfiles", ".gitignore"))
        assert os.path.exists(os.path.join(cwd(), "stuff", "mitm.py"))
        assert os.path.exists(os.path.join(cwd(), "storage"))
        assert os.path.exists(os.path.join(cwd(), "storage", "binaries"))
        assert os.path.exists(os.path.join(cwd(), "storage", "analyses"))
        assert os.path.exists(os.path.join(cwd(), "storage", "baseline"))

    def test_cuckoo_init_main(self):
        """Tests that 'cuckoo' works with a new CWD."""
        main.main(
            ("--cwd", cwd(), "--nolog"),
            standalone_mode=False
        )
        assert os.path.exists(os.path.join(cwd(), "stuff", "mitm.py"))

    @mock.patch("cuckoo.main.load_signatures")
    def test_cuckoo_init_main_nosigs(self, p):
        """Ensure load_signatures() isn't called for 'cuckoo' with new CWD."""
        main.main(
            ("--cwd", cwd(), "--nolog"),
            standalone_mode=False
        )
        assert os.path.exists(os.path.join(cwd(), "stuff", "mitm.py"))
        p.assert_not_called()

    def test_cuckoo_init_no_resultserver(self):
        """Tests that 'cuckoo init' doesn't launch the ResultServer."""
        with pytest.raises(SystemExit):
            main.main(
                ("--cwd", cwd(), "--nolog", "init"),
                standalone_mode=False
            )

        # We copy the monitor binary directory over from user-CWD (which is
        # also present in the Travis CI environment, etc) as otherwise the
        # following call will raise an exception about not having found the
        # monitoring binaries.
        shutil.rmtree(os.path.join(cwd(), "monitor"))
        shutil.copytree(
            os.path.expanduser("~/.cuckoo/monitor"),
            os.path.join(cwd(), "monitor")
        )

        # Raises CuckooCriticalError if ResultServer can't bind (which no
        # longer happens now, naturally).
        main.main(
            ("--cwd", cwd(), "--nolog", "init"),
            standalone_mode=False
        )

        assert ResultServer not in Singleton._instances

    def test_cuckoo_conf(self):
        Folders.create(cwd(), "conf")
        write_cuckoo_conf()

    def test_cuckoo_create(self):
        # Specifically try to create $CWD/signatures/__init__.pyc to ensure
        # that our .pyc filtering works.
        initpyc = os.path.join(
            cuckoo.__path__[0], "data", "signatures", "__init__.pyc"
        )
        open(initpyc, "wb").close()

        cuckoo_create("derpy")
        assert os.path.exists(cwd(".cwd"))
        assert os.path.exists(cwd("conf", "esx.conf"))
        assert os.path.exists(cwd("analyzer", "windows", "analyzer.py"))
        assert os.path.exists(cwd("monitor", "latest"))
        assert os.path.exists(cwd("distributed", "settings.py"))
        assert not os.path.exists(cwd("signatures", "__init__.pyc"))
        assert os.path.exists(initpyc)
        os.unlink(initpyc)

    def test_cuckoo_create2(self):
        cuckoo_create(cfg={
            "auxiliary": {
                "sniffer": {
                    "tcpdump": "dumping.elf",
                },
            },
        })
        buf = open(cwd("conf", "auxiliary.conf"), "rb").read()
        assert "tcpdump = dumping.elf" in buf

    def test_cuckoo_init_kv_conf(self):
        filepath = Files.temp_put(
            "cuckoo.cuckoo.version_check = no"
        )

        # Create a new CWD as Files.temp_put() indexes - or tries to - the
        # original cuckoo.conf (even though it doesn't exist yet).
        set_cwd(tempfile.mkdtemp())
        with pytest.raises(SystemExit):
            main.main(
                ("--cwd", cwd(), "init", "--conf", filepath),
                standalone_mode=False
            )

        assert config("cuckoo:cuckoo:version_check") is False

    def test_init_star_existing(self):
        cuckoo_create(cfg={
            "virtualbox": {
                "cuckoo1": {
                    "ip": "192.168.56.102",
                },
            },
        })
        assert config("virtualbox:cuckoo1:ip") == "192.168.56.102"

    def test_init_star_multiple(self):
        cuckoo_create(cfg={
            "virtualbox": {
                "virtualbox": {
                    "machines": [
                        "cuckoo2", "cuckoo3",
                    ],
                },
                "cuckoo2": {
                    "ip": "192.168.56.102",
                },
                "cuckoo3": {
                    "ip": "192.168.56.103",
                },
                "notexistingvm": {
                    "ip": "1.2.3.4",
                },
            },
        })
        assert config("virtualbox:virtualbox:machines") == [
            "cuckoo2", "cuckoo3"
        ]
        assert config("virtualbox:cuckoo2:ip") == "192.168.56.102"
        assert config("virtualbox:cuckoo3:ip") == "192.168.56.103"
        assert config("virtualbox:notexistingvm:ip") is None

class TestWriteCuckooConfiguration(object):
    def setup(self):
        set_cwd(tempfile.mkdtemp())
        mkdir(cwd("conf"))
        self.h = mock.patch("cuckoo.core.init.jinja2")
        self.p = self.h.start()
        self.render().return_value = ""

    def teardown(self):
        self.h.stop()

    def render(self):
        return self.p.Template.return_value.render

    def value(self, s):
        return self.render().call_args[0][0]["config"](s)

    def rawvalue(self, s):
        a, b, c = s.split(":")
        return self.render().call_args[0][0][a][b][c]

    def test_simple(self):
        write_cuckoo_conf(cfg={
            "cuckoo": {
                "cuckoo": {
                    "version_check": False,
                },
            },
        })
        assert self.value("cuckoo:cuckoo:version_check") is False

        with pytest.raises(ValueError):
            self.value("a")

        with pytest.raises(KeyError):
            self.value("a:b:c")

        with pytest.raises(KeyError):
            self.value("cuckoo:a:b")

        with pytest.raises(KeyError):
            self.value("cuckoo:cuckoo:c")

    def test_default_simple(self):
        write_cuckoo_conf()
        assert self.value("cuckoo:feedback:name") is None
        assert self.value("cuckoo:cuckoo:max_vmstartup_count") == 10
        assert self.rawvalue("cuckoo:cuckoo:max_vmstartup_count") == "10"

    def test_default_star(self):
        write_cuckoo_conf()
        assert self.value("routing:vpn0:name") == "vpn0"
        assert self.rawvalue("routing:vpn0:name") == "vpn0"
        assert self.value("virtualbox:cuckoo1:ip") == "192.168.56.101"
        assert self.value("avd:cuckoo1:platform") == "android"
        assert self.value("esx:analysis1:ip") == "192.168.122.101"
        assert self.value("physical:physical1:label") == "physical1"
        assert self.value("qemu:vm1:label") == "vm1"
        assert self.value("vmware:cuckoo1:vmx_path") == "../cuckoo1/cuckoo1.vmx"
        assert self.value("vsphere:analysis1:snapshot") == "snapshot_name"
        assert self.value("xenserver:cuckoo1:uuid") == "00000000-0000-0000-0000-000000000000"

    def test_star_not_found(self):
        with pytest.raises(CuckooConfigurationError) as e:
            write_cuckoo_conf(cfg={
                "routing": {
                    "vpn": {
                        "vpns": [
                            "a",
                        ],
                    },
                },
            })
        e.match("A section was defined that")

    def test_star_single(self):
        write_cuckoo_conf(cfg={
            "routing": {
                "vpn": {
                    "vpns": [
                        "a"
                    ],
                },
                "a": {
                    "description": "VPN a",
                },
            },
        })
        assert self.value("routing:vpn:vpns") == ["a"]
        assert self.rawvalue("routing:vpn:vpns") == "a"

        assert self.value("routing:a:name") is None
        assert self.rawvalue("routing:a:name") == ""

        assert self.value("routing:a:description") == "VPN a"
        assert self.rawvalue("routing:a:description") == "VPN a"

    def test_star_multiple(self):
        write_cuckoo_conf(cfg={
            "virtualbox": {
                "virtualbox": {
                    "machines": [
                        "a", "b"
                    ],
                },
                "a": {
                    "ip": "1.2.3.4",
                },
                "b": {
                    "ip": "5.6.7.8",
                },
            },
        })
        assert self.value("virtualbox:virtualbox:machines") == ["a", "b"]
        assert self.rawvalue("virtualbox:virtualbox:machines") == "a, b"

        assert self.value("virtualbox:a:ip") == "1.2.3.4"
        assert self.rawvalue("virtualbox:a:ip") == "1.2.3.4"

def test_all_config_written():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    cfg = Config.from_confdir(cwd("conf"))

    # This one is extra, ignore.
    cfg["virtualbox"].pop("honeyd", None)

    set_cwd(tempfile.mkdtemp())
    mkdir(cwd("conf"))

    lookups = []

    class LookupDict(dict):
        parents = []

        def __getitem__(self, key):
            lookups.append(":".join(self.parents + [key]))
            return dict.__getitem__(key)

    class Template(jinja2.Template):
        def render(self, kw):
            orig_config = kw["config"]

            def lookup_config(s):
                # For some reason this is called multiple times (?).
                if s not in lookups:
                    lookups.append(s)
                return orig_config(s)

            kw["config"] = lookup_config

            for key, value in kw.items():
                if key == "config":
                    continue

                for key2, value2 in value.items():
                    value[key2] = LookupDict(value2)
                    value[key2].parents = [key, key2]

            return jinja2.Template.render(self, kw)

    with mock.patch("cuckoo.core.init.jinja2") as p:
        p.Template = Template
        write_cuckoo_conf(cfg)

    for key, value in cfg.items():
        for key2, value2 in value.items():
            for key3, value3 in value2.items():
                assert "%s:%s:%s" % (key, key2, key3) in lookups

    assert sorted(lookups) == sorted(set(lookups))
