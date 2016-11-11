# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import pytest
import shutil
import tempfile

from cuckoo.common.config import Config, parse_options, emit_options, config
from cuckoo.common.exceptions import CuckooConfigurationError
from cuckoo.common.files import Folders, Files
from cuckoo.core.startup import check_configs
from cuckoo.main import main
from cuckoo.misc import set_cwd, cwd

CONF_EXAMPLE = """
[cuckoo]
delete_original = off
machine_manager = kvm
use_sniffer = no
tcpdump = /usr/sbin/tcpdump
interface = vboxnet0
"""

class TestConfig:
    def setup(self):
        set_cwd(tempfile.mkdtemp())

        self.path = tempfile.mkstemp()[1]
        open(self.path, "wb").write(CONF_EXAMPLE)

        self.c = Config(cfg=self.path)

    def test_get_option_exist(self):
        """Fetch an option of each type from default config file."""
        assert self.c.get("cuckoo")["delete_original"] is False
        assert self.c.get("cuckoo")["tcpdump"] == "/usr/sbin/tcpdump"

    def test_config_file_not_found(self):
        assert Config("foo")

    def test_get_option_not_found(self):
        with pytest.raises(CuckooConfigurationError):
            self.c.get("foo")

    def test_get_option_not_found_in_file_not_found(self):
        self.c = Config("bar")
        with pytest.raises(CuckooConfigurationError):
            self.c.get("foo")

    def test_options(self):
        assert parse_options("a=b") == {"a": "b"}
        assert parse_options("a=b,b=c") == {"a": "b", "b": "c"}
        assert parse_options("a,b") == {}

        assert emit_options({"a": "b"}) == "a=b"
        assert emit_options({"a": "b", "b": "c"}).count(",") == 1
        assert "a=b" in emit_options({"a": "b", "b": "c"})
        assert "b=c" in emit_options({"a": "b", "b": "c"})

        assert parse_options(emit_options({"x": "y"})) == {"x": "y"}

ENV_EXAMPLE = """
[cuckoo]
tmppath = foo %(CUCKOO_FOOBAR)s bar
"""

ENV2_EXAMPLE = """
[cuckoo]
tmppath = foo %(FOOBAR)s bar
"""

def test_env():
    path = tempfile.mkstemp()[1]

    os.environ["CUCKOO_FOOBAR"] = "top"
    os.environ["FOOBAR"] = "kek"

    open(path, "wb").write(ENV_EXAMPLE)
    c = Config("cuckoo", cfg=path)
    assert c.get("cuckoo")["tmppath"] == "foo top bar"

    open(path, "wb").write(ENV2_EXAMPLE)
    with pytest.raises(CuckooConfigurationError):
        Config("cuckoo", cfg=path)

VIRTUALBOX_CONFIG_EXAMPLE = """
[virtualbox]
path = /usr/bin/VBoxManage
machines = 7,8,machine1
[7]
label = 7
ip = 192.168.58.10
resultserver_port = 2042
tags = windows_xp_sp3,32_bit,acrobat_reader_6
[8]
label = 8
[machine1]
label = machine1
"""

CUCKOO_CONFIG_EXAMPLE = """
[cuckoo]
version_check = on
max_analysis_count = 0
rooter = /tmp/cuckoo-rooter
[resultserver]
force_port = no
[database]
connection =
timeout =
"""

class TestConfigType:
    def setup(self):
        set_cwd(tempfile.mkdtemp())
        Folders.create(cwd(), "conf")

        self.vbox_path = cwd("conf", "virtualbox.conf")
        open(self.vbox_path, "wb").write(VIRTUALBOX_CONFIG_EXAMPLE)
        self.virtualbox = Config(file_name="virtualbox", cfg=self.vbox_path)

        filepath = cwd("conf", "cuckoo.conf")
        open(filepath, "wb").write(CUCKOO_CONFIG_EXAMPLE)
        self.cuckoo = Config(file_name="cuckoo", cfg=filepath)

    def test_integer_parse(self):
        """Testing the integer parsing in the configuration file parsing."""
        assert self.virtualbox.get("virtualbox")["machines"] == "7,8,machine1"
        assert self.virtualbox.get("7") is not None
        assert self.virtualbox.get("7")["label"] is "7"
        assert self.virtualbox.get("7")["resultserver_port"] == 2042
        assert self.virtualbox.get("8") is not None
        assert self.virtualbox.get("8")["label"] is "8"
        assert self.virtualbox.get("machine1") is not None
        assert self.virtualbox.get("machine1")["label"] == "machine1"

    def test_config_wrapper(self):
        assert config("virtualbox:7:label") == "7"
        assert config("virtualbox:7:ip") == "192.168.58.10"
        assert config("virtualbox:7:resultserver_port") == 2042

        assert config("cuckoo:notasection:hello") is None
        assert config("cuckoo:cuckoo:notafield") is None

    def test_string_parse(self):
        """Testing the string parsing in the configuration file parsing."""
        assert self.virtualbox.get("virtualbox")["path"] == "/usr/bin/VBoxManage"
        assert self.virtualbox.get("7")["ip"] == "192.168.58.10"
        assert self.virtualbox.get("7")["tags"] == "windows_xp_sp3,32_bit,acrobat_reader_6"

    def test_boolean_parse(self):
        """Testing the boolean parsing in the configuration file parsing."""
        assert self.cuckoo.get("cuckoo")["version_check"] is True
        assert self.cuckoo.get("cuckoo")["max_analysis_count"] is not False
        assert self.cuckoo.get("resultserver")["force_port"] is False

    def test_path_parse(self):
        """Testing the Path parsing in the configuration file parsing."""
        assert self.virtualbox.get("virtualbox")["path"] == "/usr/bin/VBoxManage"
        assert self.cuckoo.get("cuckoo")["rooter"] == "/tmp/cuckoo-rooter"

def test_default_config():
    """Test the default configuration."""
    dirpath = tempfile.mkdtemp()

    with pytest.raises(SystemExit):
        main.main(
            ("--cwd", dirpath, "--nolog", "init"),
            standalone_mode=False
        )

    assert config("cuckoo:cuckoo:version_check") is True
    assert config("cuckoo:cuckoo:tmppath") == "/tmp"
    assert config("cuckoo:resultserver:ip") == "192.168.56.1"
    assert config("cuckoo:processing:analysis_size_limit") == 104857600
    assert config("cuckoo:timeouts:critical") == 60
    assert config("auxiliary:mitm:mitmdump") == "/usr/local/bin/mitmdump"

    with pytest.raises(RuntimeError):
        config("nope")

    with pytest.raises(RuntimeError):
        config("nope:nope")

    assert check_configs()

    Files.create(
        os.path.join(dirpath, "conf"), "cuckoo.conf",
        "[cuckoo]\nversion_check = on"
    )
    with pytest.raises(CuckooConfigurationError):
        check_configs()

def test_invalid_section():
    set_cwd(tempfile.mkdtemp())
    Folders.create(cwd(), "conf")

    Files.create(cwd("conf"), "cuckoo.conf", "[invalid_section]\nfoo = bar")
    with pytest.raises(CuckooConfigurationError):
        Config("cuckoo", strict=True)

    Files.create(cwd("conf"), "cuckoo.conf", "[cucko]\ninvalid = entry")
    with pytest.raises(CuckooConfigurationError):
        Config("cuckoo", strict=True)
