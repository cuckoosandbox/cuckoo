# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import pytest
import tempfile

from cuckoo.common.config import Config, parse_options, emit_options
from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.misc import set_cwd

CONF_EXAMPLE = """
[cuckoo]
debug = off
analysis_timeout = 120
critical_timeout = 600
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
        assert self.c.get("cuckoo")["debug"] is False
        assert self.c.get("cuckoo")["tcpdump"] == "/usr/sbin/tcpdump"
        assert self.c.get("cuckoo")["critical_timeout"] == 600

    def test_config_file_not_found(self):
        assert Config("foo")

    def test_get_option_not_found(self):
        with pytest.raises(CuckooOperationalError):
            self.c.get("foo")

    def test_get_option_not_found_in_file_not_found(self):
        self.c = Config("bar")
        with pytest.raises(CuckooOperationalError):
            self.c.get("foo")

    def test_options(self):
        assert parse_options("a=b") == {"a": "b"}
        assert parse_options("a=b,b=c") == {"a": "b", "b": "c"}

        assert emit_options({"a": "b"}) == "a=b"
        assert emit_options({"a": "b", "b": "c"}).count(",") == 1
        assert "a=b" in emit_options({"a": "b", "b": "c"})
        assert "b=c" in emit_options({"a": "b", "b": "c"})

        assert parse_options(emit_options({"x": "y"})) == {"x": "y"}

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

        self.path = tempfile.mkstemp()[1]
        open(self.path, "wb").write(VIRTUALBOX_CONFIG_EXAMPLE)
        self.c = Config(file_name="virtualbox", cfg=self.path)

        self.path = tempfile.mkstemp()[1]
        open(self.path, "wb").write(CUCKOO_CONFIG_EXAMPLE)
        self.f = Config(file_name="cuckoo", cfg=self.path)

    def test_integer_parse(self):
        """Testing the integer parsing in the configuration file parsing."""
        assert self.c.get("virtualbox")["machines"] == "7,8,machine1"
        assert self.c.get("7") is not None
        assert self.c.get("7")["label"] is "7"
        assert self.c.get("7")["resultserver_port"] == 2042
        assert self.c.get("8") is not None
        assert self.c.get("8")["label"] is "8"
        assert self.c.get("machine1") is not None
        assert self.c.get("machine1")["label"] == "machine1"

    def test_string_parse(self):
        """Testing the string parsing in the configuration file parsing."""
        assert self.c.get("virtualbox")["path"] == "/usr/bin/VBoxManage"
        assert self.c.get("7")["ip"] == "192.168.58.10"
        assert self.c.get("7")["tags"] == "windows_xp_sp3,32_bit,acrobat_reader_6"

    def test_boolean_parse(self):
        """Testing the boolean parsing in the configuration file parsing."""
        assert self.f.get("cuckoo")["version_check"] is True
        assert self.f.get("cuckoo")["max_analysis_count"] is not False
        assert self.f.get("resultserver")["force_port"] is False

    def test_path_parse(self):
        """Testing the Path parsing in the configuration file parsing."""
        assert self.c.get("virtualbox")["path"] == "/usr/bin/VBoxManage"
        assert self.f.get("cuckoo")["rooter"] == "/tmp/cuckoo-rooter"
