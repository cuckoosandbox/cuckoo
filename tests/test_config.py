# Copyright (C) 2016-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import os
import pytest
import tempfile

from cuckoo.common.config import (
    Config, parse_options, emit_options, config, cast, Path, read_kv_conf,
    config2, List, String, _cache
)
from cuckoo.common.constants import faq
from cuckoo.common.exceptions import (
    CuckooConfigurationError, CuckooStartupError
)
from cuckoo.common.files import Folders, Files
from cuckoo.compat.config import migrate
from cuckoo.core.init import write_cuckoo_conf
from cuckoo.core.startup import check_configs
from cuckoo.main import main, cuckoo_create
from cuckoo.misc import set_cwd, cwd, mkdir

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
        with pytest.raises(CuckooConfigurationError) as e:
            self.c.get("foo")
        e.match("not found in configuration")

    def test_get_option_not_found_in_file_not_found(self):
        self.c = Config("bar")
        with pytest.raises(CuckooConfigurationError) as e:
            self.c.get("foo")
        e.match("not found in configuration")

    def test_options(self):
        assert parse_options("a=b") == {"a": "b"}
        assert parse_options("a=b,b=c") == {"a": "b", "b": "c"}
        assert parse_options("a,b") == {}

        assert emit_options({"a": "b"}) == "a=b"
        assert emit_options({"a": "b", "b": "c"}) == "a=b,b=c"

        assert parse_options(emit_options({"x": "y"})) == {"x": "y"}

ENV_EXAMPLE = """
[cuckoo]
tmppath = %(CUCKOO_CWD)s/foo%(CUCKOO_FOOBAR)sbar
"""

ENV2_EXAMPLE = """
[cuckoo]
tmppath = %(CUCKOO_CWD)s/foo%(FOOBAR)sbar
"""

def test_env():
    path = tempfile.mkstemp()[1]

    os.environ["CUCKOO_FOOBAR"] = "top"
    os.environ["FOOBAR"] = "kek"

    mkdir(cwd("footopbar"))

    open(path, "wb").write(ENV_EXAMPLE)
    c = Config("cuckoo", cfg=path)
    assert c.get("cuckoo")["tmppath"] == cwd() + "/footopbar"

    open(path, "wb").write(ENV2_EXAMPLE)
    with pytest.raises(CuckooConfigurationError) as e:
        Config("cuckoo", cfg=path)
    e.match("Missing environment variable")

    os.environ.pop("FOOBAR")
    os.environ.pop("CUCKOO_FOOBAR")

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
tmppath =
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
        assert self.virtualbox.get("virtualbox")["machines"] == ["7", "8", "machine1"]
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
    assert config("cuckoo:cuckoo:tmppath") is None
    assert config("cuckoo:resultserver:ip") == "192.168.56.1"
    assert config("cuckoo:processing:analysis_size_limit") == 128*1024*1024
    assert config("cuckoo:timeouts:critical") == 60
    assert config("auxiliary:mitm:mitmdump") == "/usr/local/bin/mitmdump"

    with pytest.raises(RuntimeError) as e:
        config("nope")
    e.match("Invalid configuration entry")

    with pytest.raises(RuntimeError) as e:
        config("nope:nope")
    e.match("Invalid configuration entry")

    assert check_configs()

    os.remove(os.path.join(dirpath, "conf", "cuckoo.conf"))
    with pytest.raises(CuckooStartupError) as e:
        check_configs()
    e.match("Config file does not exist")

    Files.create(
        (dirpath, "conf"), "cuckoo.conf", "[cuckoo]\nversion_check = on"
    )
    assert check_configs()

def test_invalid_section():
    set_cwd(tempfile.mkdtemp())
    Folders.create(cwd(), "conf")

    Files.create(cwd("conf"), "cuckoo.conf", "[invalid_section]\nfoo = bar")
    with pytest.raises(CuckooConfigurationError) as e:
        Config("cuckoo", strict=True)
    e.match("Config section.*not found")

    Files.create(cwd("conf"), "cuckoo.conf", "[cuckoo]\ninvalid = entry")
    with pytest.raises(CuckooConfigurationError) as e:
        config("cuckoo:invalid:entry", strict=True)
    e.match("No such configuration value exists")

def test_confdir():
    set_cwd(tempfile.mkdtemp())
    Folders.create(cwd(), "conf")
    Files.create(
        cwd("conf"), "cuckoo.conf",
        "[cuckoo]\ndelete_original = yes"
    )
    Files.create(
        cwd("conf"), "virtualbox.conf",
        "[virtualbox]\npath = /usr/bin/VBoxManage"
    )
    cfg = Config.from_confdir(cwd("conf"))
    assert cfg["cuckoo"]["cuckoo"]["delete_original"] is True
    assert cfg["virtualbox"]["virtualbox"]["path"] == "/usr/bin/VBoxManage"

def test_unknown_section():
    Files.create(
        cwd("conf"), "cuckoo.conf",
        "[virtualbox]\npath = /usr/bin/VBoxManage"
    )
    cfg = Config.from_confdir(cwd("conf"))
    assert "virtualbox" not in cfg["cuckoo"]

    cfg = Config.from_confdir(cwd("conf"), loose=True)
    assert cfg["cuckoo"]["virtualbox"]["path"] == "/usr/bin/VBoxManage"

def test_unknown_conf_file():
    Files.create(
        cwd("conf"), "foobar.conf",
        "[derp]\nfoo = bar"
    )
    cfg = Config.from_confdir(cwd("conf"))
    assert "derp" not in cfg["foobar"]

    cfg = Config.from_confdir(cwd("conf"), loose=True)
    assert cfg["foobar"]["derp"]["foo"] == "bar"

def test_sanitize():
    set_cwd(tempfile.mkdtemp())
    Folders.create(cwd(), "conf")
    Files.create(
        cwd("conf"), "cuckoo.conf",
        "[database]\n"
        "timeout = 42\n"
        "connection = postgresql://user:pass@localhost/cuckoo"
    )
    cfg = Config.from_confdir(cwd("conf"))
    assert cfg["cuckoo"]["database"]["timeout"] == 42
    assert cfg["cuckoo"]["database"]["connection"] == "postgresql://user:pass@localhost/cuckoo"

    cfg = Config.from_confdir(cwd("conf"), sanitize=True)
    assert cfg["cuckoo"]["database"]["timeout"] == 42
    assert cfg["cuckoo"]["database"]["connection"] == "*"*8

def test_invalid_machinery():
    set_cwd(tempfile.mkdtemp())
    Folders.create(cwd(), "conf")
    write_cuckoo_conf({
        "cuckoo": {
            "cuckoo": {
                "machinery": "foobar",
            },
        },
    })
    with pytest.raises(CuckooStartupError) as e:
        check_configs()
    e.match("unknown machinery")

def test_invalid_feedback():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "cuckoo": {
            "feedback": {
                "enabled": True,
                "name": "foo",
                "email": "a@b.com!",
            }
        }
    })
    with pytest.raises(CuckooStartupError) as e:
        check_configs()
    e.match("Cuckoo Feedback configuration")

def test_whitespace_before_line():
    set_cwd(tempfile.mkdtemp())
    filepath = Files.temp_put("""
[virtualbox]
machines = cuckoo1
[cuckoo1]
label = cuckoo1
ip = 1.2.3.4
 snapshot = asnapshot
""")
    with pytest.raises(CuckooConfigurationError) as e:
        Config(file_name="virtualbox", cfg=filepath)
    e.match("error reading in the")

def test_whitespace_before_line2():
    set_cwd(tempfile.mkdtemp())
    filepath = Files.temp_put("""
[virtualbox]
machines = cuckoo1
[cuckoo1]
 label = cuckoo1
ip = 1.2.3.4
snapshot = asnapshot
""")
    with pytest.raises(CuckooConfigurationError) as e:
        Config(file_name="virtualbox", cfg=filepath)
    e.match("Most likely there are leading whitespaces")

def test_migration_041_042():
    set_cwd(tempfile.mkdtemp())
    Folders.create(cwd(), "conf")
    Files.create(
        cwd("conf"), "cuckoo.conf",
        "[cuckoo]\ndelete_original = yes"
    )
    Files.create(
        cwd("conf"), "virtualbox.conf",
        "[virtualbox]\npath = /usr/bin/VBoxManage"
    )
    cfg = Config.from_confdir(cwd("conf"), loose=True)
    cfg = migrate(cfg, "0.4.1", "0.4.2")
    assert cfg["cuckoo"]["cuckoo"]["analysis_size_limit"] == 104857600
    assert cfg["virtualbox"]["virtualbox"]["timeout"] == 300
    assert cfg["vmware"]["vmware"]["mode"] == "gui"
    assert cfg["vmware"]["vmware"]["path"] == "/usr/bin/vmrun"
    assert cfg["vmware"]["vmware"]["machines"] == ["cuckoo1"]
    assert cfg["vmware"]["cuckoo1"]["label"] == "../vmware-xp3.vmx,Snapshot1"
    assert cfg["vmware"]["cuckoo1"]["platform"] == "windows"
    assert cfg["vmware"]["cuckoo1"]["ip"] == "192.168.54.111"

def test_migration_042_050():
    set_cwd(tempfile.mkdtemp())
    Folders.create(cwd(), "conf")
    Files.create(cwd("conf"), "cuckoo.conf", """
[cuckoo]
delete_original = yes
analysis_timeout = 122
critical_timeout = 601
analysis_size_limit = 123456
use_sniffer = no
""")
    Files.create(cwd("conf"), "virtualbox.conf", """
[virtualbox]
path = /usr/bin/VBoxManage
timeout = 1337
""")
    cfg = Config.from_confdir(cwd("conf"), loose=True)
    cfg = migrate(cfg, "0.4.2", "0.5.0")
    assert "analysis_timeout" not in cfg["cuckoo"]["cuckoo"]
    assert cfg["cuckoo"]["cuckoo"]["version_check"] is True
    assert cfg["cuckoo"]["cuckoo"]["memory_dump"] is False
    assert "analysis_size_limit" not in cfg["cuckoo"]["cuckoo"]
    assert cfg["cuckoo"]["processing"]["analysis_size_limit"] == "123456"
    assert cfg["cuckoo"]["processing"]["resolve_dns"] is True
    assert cfg["cuckoo"]["database"]["connection"] is None
    assert cfg["cuckoo"]["database"]["timeout"] is None
    assert cfg["cuckoo"]["timeouts"]["default"] == 122
    assert cfg["cuckoo"]["timeouts"]["critical"] == 601
    assert cfg["cuckoo"]["timeouts"]["vm_state"] == 1337
    assert "use_sniffer" not in cfg["cuckoo"]["cuckoo"]
    assert cfg["cuckoo"]["sniffer"]["enabled"] == "no"
    assert cfg["cuckoo"]["sniffer"]["tcpdump"] == "/usr/sbin/tcpdump"
    assert cfg["cuckoo"]["sniffer"]["interface"] == "vboxnet0"
    assert cfg["cuckoo"]["sniffer"]["bpf"] is None
    assert cfg["cuckoo"]["graylog"]["enabled"] is False
    assert cfg["cuckoo"]["graylog"]["host"] == "localhost"
    assert cfg["cuckoo"]["graylog"]["port"] == 12201
    assert cfg["cuckoo"]["graylog"]["level"] == "error"
    assert "timeout" not in cfg["virtualbox"]["virtualbox"]

def test_migration_050_060():
    set_cwd(tempfile.mkdtemp())
    Folders.create(cwd(), "conf")
    Files.create(cwd("conf"), "cuckoo.conf", "[cuckoo]")
    cfg = Config.from_confdir(cwd("conf"), loose=True)
    cfg = migrate(cfg, "0.5.0", "0.6.0")
    assert cfg["cuckoo"]["resultserver"] == {
        "ip": "192.168.56.1",
        "port": 2042,
        "store_csvs": False,
        "upload_max_size": 10485760,
    }
    assert cfg["processing"] == {
        "analysisinfo": {
            "enabled": True,
        },
        "behavior": {
            "enabled": True,
        },
        "debug": {
            "enabled": True,
        },
        "dropped": {
            "enabled": True,
        },
        "network": {
            "enabled": True,
        },
        "static": {
            "enabled": True,
        },
        "strings": {
            "enabled": True,
        },
        "targetinfo": {
            "enabled": True,
        },
        "virustotal": {
            "enabled": True,
            "key": "a0283a2c3d55728300d064874239b5346fb991317e8449fe43c902879d758088",
        },
    }

def test_migration_060_100():
    set_cwd(tempfile.mkdtemp())
    Folders.create(cwd(), "conf")
    Files.create(cwd("conf"), "cuckoo.conf", """
[cuckoo]
delete_original = on
machine_manager = hello
[sniffer]
enabled = no
tcpdump = /wow/path
interface = vboxnet0
[graylog]
enabled = no
host = localhost
port = 12201
level = info
""")
    Files.create(cwd("conf"), "processing.conf", """
[dropped]
enabled = yes
""")
    Files.create(cwd("conf"), "reporting.conf", """
[pickled]
enabled = off
[metadata]
enabled = off
[maec11]
enabled = off
[mongodb]
enabled = on
""")
    Files.create(cwd("conf"), "vmware.conf", """
[vmware]
machines = hello
[hello]
label = label,snapshot
""")
    cfg = Config.from_confdir(cwd("conf"), loose=True)
    assert "machine_manager" in cfg["cuckoo"]["cuckoo"]
    assert "sniffer" in cfg["cuckoo"]
    assert "graylog" in cfg["cuckoo"]
    assert "pickled" in cfg["reporting"]
    assert "metadata" in cfg["reporting"]
    assert "maec11" in cfg["reporting"]
    cfg = migrate(cfg, "0.6.0", "1.0.0")
    assert cfg["auxiliary"]["sniffer"]["enabled"] is False
    assert cfg["auxiliary"]["sniffer"]["tcpdump"] == "/wow/path"
    assert cfg["auxiliary"]["sniffer"]["interface"] == "vboxnet0"
    assert cfg["cuckoo"]["cuckoo"]["delete_bin_copy"] is False
    assert "machine_manager" not in cfg["cuckoo"]["cuckoo"]
    assert cfg["cuckoo"]["cuckoo"]["machinery"] == "hello"
    assert cfg["cuckoo"]["cuckoo"]["reschedule"] is False
    assert cfg["cuckoo"]["cuckoo"]["process_results"] is True
    assert cfg["cuckoo"]["cuckoo"]["max_analysis_count"] == 0
    assert cfg["cuckoo"]["cuckoo"]["freespace"] == 64
    assert "sniffer" not in cfg["cuckoo"]
    assert "graylog" not in cfg["cuckoo"]
    assert cfg["esx"]["esx"]["dsn"] == "esx://127.0.0.1/?no_verify=1"
    assert cfg["esx"]["esx"]["username"] == "username_goes_here"
    assert cfg["esx"]["esx"]["password"] == "password_goes_here"
    assert cfg["esx"]["esx"]["machines"] == ["analysis1"]
    assert cfg["esx"]["analysis1"]["label"] == "cuckoo1"
    assert cfg["esx"]["analysis1"]["platform"] == "windows"
    assert cfg["esx"]["analysis1"]["snapshot"] == "clean_snapshot"
    assert cfg["esx"]["analysis1"]["ip"] == "192.168.122.105"
    assert cfg["memory"]["basic"]["guest_profile"] == "WinXPSP2x86"
    assert cfg["memory"]["basic"]["delete_memdump"] is False
    assert cfg["memory"]["malfind"]["enabled"] is True
    assert cfg["memory"]["malfind"]["filter"] is True
    assert cfg["memory"]["apihooks"]["enabled"] is False
    assert cfg["memory"]["apihooks"]["filter"] is True
    assert cfg["memory"]["pslist"]["enabled"] is True
    assert cfg["memory"]["pslist"]["filter"] is False
    assert cfg["memory"]["psxview"]["enabled"] is True
    assert cfg["memory"]["psxview"]["filter"] is False
    assert cfg["memory"]["callbacks"]["enabled"] is True
    assert cfg["memory"]["callbacks"]["filter"] is False
    assert cfg["memory"]["idt"]["enabled"] is True
    assert cfg["memory"]["idt"]["filter"] is False
    assert cfg["memory"]["timers"]["enabled"] is True
    assert cfg["memory"]["timers"]["filter"] is False
    assert cfg["memory"]["messagehooks"]["enabled"] is False
    assert cfg["memory"]["messagehooks"]["filter"] is False
    assert cfg["memory"]["getsids"]["enabled"] is True
    assert cfg["memory"]["getsids"]["filter"] is False
    assert cfg["memory"]["privs"]["enabled"] is True
    assert cfg["memory"]["privs"]["filter"] is False
    assert cfg["memory"]["dlllist"]["enabled"] is True
    assert cfg["memory"]["dlllist"]["filter"] is True
    assert cfg["memory"]["handles"]["enabled"] is True
    assert cfg["memory"]["handles"]["filter"] is True
    assert cfg["memory"]["ldrmodules"]["enabled"] is True
    assert cfg["memory"]["ldrmodules"]["filter"] is True
    assert cfg["memory"]["mutantscan"]["enabled"] is True
    assert cfg["memory"]["mutantscan"]["filter"] is True
    assert cfg["memory"]["devicetree"]["enabled"] is True
    assert cfg["memory"]["devicetree"]["filter"] is True
    assert cfg["memory"]["svcscan"]["enabled"] is True
    assert cfg["memory"]["svcscan"]["filter"] is True
    assert cfg["memory"]["modscan"]["enabled"] is True
    assert cfg["memory"]["modscan"]["filter"] is True
    assert cfg["memory"]["mask"]["enabled"] is False
    assert cfg["memory"]["mask"]["pid_generic"] is None
    assert cfg["processing"]["memory"]["enabled"] is False
    assert "pickled" not in cfg["reporting"]
    assert "metadata" not in cfg["reporting"]
    assert "maec11" not in cfg["reporting"]
    assert cfg["reporting"]["mmdef"]["enabled"] is False
    assert cfg["reporting"]["maec41"]["enabled"] is False
    assert cfg["reporting"]["maec41"]["mode"] == "overview"
    assert cfg["reporting"]["maec41"]["processtree"] is True
    assert cfg["reporting"]["maec41"]["output_handles"] is False
    assert cfg["reporting"]["maec41"]["static"] is True
    assert cfg["reporting"]["maec41"]["strings"] is True
    assert cfg["reporting"]["maec41"]["virustotal"] is True
    assert cfg["reporting"]["mongodb"]["host"] == "127.0.0.1"
    assert cfg["reporting"]["mongodb"]["port"] == 27017
    assert cfg["vmware"]["vmware"]["machines"] == ["hello"]
    assert cfg["vmware"]["hello"]["label"] == "label"
    assert cfg["vmware"]["hello"]["snapshot"] == "snapshot"

def test_migration_100_110():
    set_cwd(tempfile.mkdtemp())
    Folders.create(cwd(), "conf")
    Files.create(cwd("conf"), "cuckoo.conf", """
[cuckoo]
delete_original = on
""")
    cfg = Config.from_confdir(cwd("conf"), loose=True)
    cfg = migrate(cfg, "1.0.0", "1.1.0")
    assert cfg["cuckoo"]["cuckoo"]["tmppath"] == "/tmp"

def test_migration_110_120():
    set_cwd(tempfile.mkdtemp())
    Folders.create(cwd(), "conf")
    Files.create(cwd("conf"), "cuckoo.conf", """
[cuckoo]
delete_original = on
memory_dump = off
[processing]
analysis_size_limit = 1234
""")
    Files.create(cwd("conf"), "memory.conf", """
[malfind]
enabled = yes
filter = on
""")
    Files.create(cwd("conf"), "processing.conf", """
[network]
enabled = yes
[virustotal]
enabled = yes
""")
    Files.create(cwd("conf"), "reporting.conf", """
[jsondump]
enabled = yes
[mongodb]
enabled = yes
host = localhost
port = 27017
[hpfclient]
enabled = yes
foo = bar
""")
    Files.create(cwd("conf"), "vmware.conf", """
[vmware]
machines = hello
[hello]
label = label
snapshot = snapshot
""")
    cfg = Config.from_confdir(cwd("conf"), loose=True)
    assert "hpfclient" in cfg["reporting"]
    cfg = migrate(cfg, "1.1.0", "1.2.0")
    assert cfg["cuckoo"]["cuckoo"]["terminate_processes"] is False
    assert cfg["cuckoo"]["cuckoo"]["max_machines_count"] == 0
    assert cfg["cuckoo"]["processing"]["sort_pcap"] is True
    assert cfg["memory"]["yarascan"]["enabled"] is True
    assert cfg["memory"]["yarascan"]["filter"] is True
    assert cfg["memory"]["ssdt"]["enabled"] is True
    assert cfg["memory"]["ssdt"]["filter"] is True
    assert cfg["memory"]["gdt"]["enabled"] is True
    assert cfg["memory"]["gdt"]["filter"] is True
    assert cfg["physical"]["physical"]["machines"] == ["physical1"]
    assert cfg["physical"]["physical"]["user"] == "username"
    assert cfg["physical"]["physical"]["password"] == "password"
    assert cfg["physical"]["physical1"]["label"] == "physical1"
    assert cfg["physical"]["physical1"]["platform"] == "windows"
    assert cfg["physical"]["physical1"]["ip"] == "192.168.56.101"
    assert cfg["processing"]["procmemory"]["enabled"] is True
    assert cfg["processing"]["virustotal"]["timeout"] == 60
    assert cfg["reporting"]["jsondump"]["indent"] == 4
    assert cfg["reporting"]["jsondump"]["encoding"] == "latin-1"
    assert cfg["reporting"]["mongodb"]["db"] == "cuckoo"
    assert cfg["reporting"]["mongodb"]["store_memdump"] is True
    assert "hpfclient" not in cfg["reporting"]
    assert cfg["vmware"]["hello"]["vmx_path"] == "label"
    assert cfg["xenserver"]["xenserver"]["user"] == "root"
    assert cfg["xenserver"]["xenserver"]["password"] == "changeme"
    assert cfg["xenserver"]["xenserver"]["url"] == "https://xenserver"
    assert cfg["xenserver"]["xenserver"]["machines"] == ["cuckoo1"]
    assert cfg["xenserver"]["cuckoo1"]["uuid"] == "00000000-0000-0000-0000-000000000000"
    assert cfg["xenserver"]["cuckoo1"]["platform"] == "windows"
    assert cfg["xenserver"]["cuckoo1"]["ip"] == "192.168.54.111"
    assert cfg["xenserver"]["xenserver"]["user"] == "root"

def test_migration_120_20c1():
    set_cwd(tempfile.mkdtemp())
    Folders.create(cwd(), "conf")
    Files.create(cwd("conf"), "auxiliary.conf", """
[sniffer]
interface = foobar
""")
    Files.create(cwd("conf"), "cuckoo.conf", """
[cuckoo]
delete_original = on
memory_dump = off
[processing]
analysis_size_limit = 1234
[resultserver]
store_csvs = yes
[timeouts]
vm_state = 300
""")
    Files.create(cwd("conf"), "esx.conf", """
[esx]
machines = analysis1
""")
    Files.create(cwd("conf"), "kvm.conf", """
[kvm]
machines = analysis1
""")
    Files.create(cwd("conf"), "memory.conf", """
[malfind]
enabled = yes
filter = on
""")
    Files.create(cwd("conf"), "physical.conf", """
[physical]
user = username
""")
    Files.create(cwd("conf"), "processing.conf", """
[network]
enabled = yes
[virustotal]
enabled = yes
[procmemory]
enabled = no
""")
    Files.create(cwd("conf"), "reporting.conf", """
[reporthtml]
enabled = yes
[mmdef]
enabled = no
[maec41]
enabled = no
[mongodb]
enabled = no
host = 127.0.0.1
port = 27017
db = cuckoo
store_memdump = no
[jsondump]
enabled = yes
""")
    Files.create(cwd("conf"), "virtualbox.conf", """
[virtualbox]
mode = gui
""")
    Files.create(cwd("conf"), "vmware.conf", """
[vmware]
machines = hello
[hello]
label = label
snapshot = snapshot
""")
    Files.create(cwd("conf"), "xenserver.conf", """
[xenserver]
machines = cuckoo1
""")
    cfg = Config.from_confdir(cwd("conf"), loose=True)
    assert "store_csvs" in cfg["cuckoo"]["resultserver"]
    assert "mmdef" in cfg["reporting"]
    assert "maec41" in cfg["reporting"]
    cfg = migrate(cfg, "1.2.0", "2.0-rc1")
    assert "interface" not in cfg["auxiliary"]["sniffer"]
    assert cfg["auxiliary"]["mitm"]["enabled"] is False
    assert cfg["auxiliary"]["mitm"]["mitmdump"] == "/usr/local/bin/mitmdump"
    assert cfg["auxiliary"]["mitm"]["port_base"] == 50000
    assert cfg["auxiliary"]["mitm"]["script"] == "data/mitm.py"
    assert cfg["auxiliary"]["mitm"]["certificate"] == "bin/cert.p12"
    assert cfg["auxiliary"]["services"]["enabled"] is False
    assert cfg["auxiliary"]["services"]["services"] == "honeyd"
    assert cfg["auxiliary"]["services"]["timeout"] == 0
    assert cfg["avd"]["avd"]["mode"] == "headless"
    assert cfg["avd"]["avd"]["emulator_path"] == "/home/cuckoo/android-sdk-linux/tools/emulator"
    assert cfg["avd"]["avd"]["adb_path"] == "/home/cuckoo/android-sdk-linux/platform-tools/adb"
    assert cfg["avd"]["avd"]["avd_path"] == "/home/cuckoo/.android/avd"
    assert cfg["avd"]["avd"]["reference_machine"] == "cuckoo-bird"
    assert cfg["avd"]["avd"]["machines"] == ["cuckoo1"]
    assert cfg["avd"]["cuckoo1"]["label"] == "cuckoo1"
    assert cfg["avd"]["cuckoo1"]["platform"] == "android"
    assert cfg["avd"]["cuckoo1"]["ip"] == "127.0.0.1"
    assert cfg["avd"]["cuckoo1"]["emulator_port"] == 5554
    assert cfg["avd"]["cuckoo1"]["resultserver_ip"] == "10.0.2.2"
    assert cfg["avd"]["cuckoo1"]["resultserver_port"] == 2042
    assert cfg["cuckoo"]["cuckoo"]["max_vmstartup_count"] == 10
    assert cfg["cuckoo"]["cuckoo"]["rooter"] == "/tmp/cuckoo-rooter"
    assert cfg["cuckoo"]["routing"]["route"] == "none"
    assert cfg["cuckoo"]["routing"]["internet"] == "none"
    assert "store_csvs" not in cfg["cuckoo"]["resultserver"]
    assert cfg["cuckoo"]["timeouts"]["vm_state"] == 60
    assert cfg["esx"]["esx"]["interface"] == "eth0"
    assert cfg["kvm"]["kvm"]["interface"] == "virbr0"
    assert cfg["memory"]["sockscan"]["enabled"] is True
    assert cfg["memory"]["sockscan"]["filter"] is False
    assert cfg["memory"]["netscan"]["enabled"] is True
    assert cfg["memory"]["netscan"]["filter"] is False
    assert cfg["physical"]["physical"]["interface"] == "eth0"
    assert cfg["physical"]["fog"]["hostname"] == "none"
    assert cfg["physical"]["fog"]["username"] == "fog"
    assert cfg["physical"]["fog"]["password"] == "password"
    assert cfg["processing"]["apkinfo"]["enabled"] is False
    assert cfg["processing"]["apkinfo"]["decompilation_threshold"] == 5000000
    assert cfg["processing"]["baseline"]["enabled"] is False
    assert cfg["processing"]["buffer"]["enabled"] is True
    assert cfg["processing"]["droidmon"]["enabled"] is False
    assert cfg["processing"]["dumptls"]["enabled"] is True
    assert cfg["processing"]["googleplay"]["enabled"] is False
    assert cfg["processing"]["googleplay"]["android_id"] is None
    assert cfg["processing"]["googleplay"]["google_login"] is None
    assert cfg["processing"]["googleplay"]["google_password"] is None
    assert cfg["processing"]["procmemory"]["idapro"] is False
    assert cfg["processing"]["screenshots"]["enabled"] is False
    assert cfg["processing"]["screenshots"]["tesseract"] == "/usr/bin/tesseract"
    assert cfg["processing"]["snort"]["enabled"] is False
    assert cfg["processing"]["snort"]["snort"] == "/usr/local/bin/snort"
    assert cfg["processing"]["snort"]["conf"] == "/etc/snort/snort.conf"
    assert cfg["processing"]["suricata"]["enabled"] is False
    assert cfg["processing"]["suricata"]["suricata"] == "/usr/bin/suricata"
    assert cfg["processing"]["suricata"]["conf"] == "/etc/suricata/suricata.yaml"
    assert cfg["processing"]["suricata"]["eve_log"] == "eve.json"
    assert cfg["processing"]["suricata"]["files_log"] == "files-json.log"
    assert cfg["processing"]["suricata"]["files_dir"] == "files"
    assert cfg["processing"]["suricata"]["socket"] is None
    assert cfg["processing"]["virustotal"]["scan"] is False
    assert cfg["qemu"]["qemu"]["path"] == "/usr/bin/qemu-system-x86_64"
    assert cfg["qemu"]["qemu"]["machines"] == ["vm1", "vm2"]
    assert cfg["qemu"]["qemu"]["interface"] == "qemubr"
    assert cfg["qemu"]["vm1"]["label"] == "vm1"
    assert cfg["qemu"]["vm1"]["image"] == "/home/rep/vms/qvm_wheezy64_1.qcow2"
    assert cfg["qemu"]["vm1"]["platform"] == "linux"
    assert cfg["qemu"]["vm1"]["ip"] == "192.168.55.2"
    assert cfg["qemu"]["vm1"]["interface"] == "qemubr"
    assert cfg["qemu"]["vm1"]["resultserver_ip"] == "192.168.55.1"
    assert cfg["qemu"]["vm1"]["tags"] == "debian_wheezy,64_bit"
    assert cfg["qemu"]["vm2"]["label"] == "vm2"
    assert cfg["qemu"]["vm2"]["image"] == "/home/rep/vms/qvm_wheezy64_1.qcow2"
    assert cfg["qemu"]["vm2"]["arch"] == "mipsel"
    assert cfg["qemu"]["vm2"]["kernel_path"] == "{imagepath}/vmlinux-3.16.0-4-4kc-malta-mipsel"
    assert cfg["qemu"]["vm2"]["platform"] == "linux"
    assert cfg["qemu"]["vm2"]["ip"] == "192.168.55.3"
    assert cfg["qemu"]["vm2"]["interface"] == "qemubr"
    assert cfg["qemu"]["vm2"]["tags"] == "debian_wheezy,mipsel"
    assert "mmdef" not in cfg["reporting"]
    assert "maec41" not in cfg["reporting"]
    assert cfg["reporting"]["reporthtml"]["enabled"] is False
    assert cfg["reporting"]["mongodb"]["store_memdump"] is False
    assert cfg["reporting"]["mongodb"]["paginate"] == 100
    assert cfg["reporting"]["moloch"]["enabled"] is False
    assert cfg["virtualbox"]["virtualbox"]["mode"] == "headless"
    assert cfg["virtualbox"]["virtualbox"]["interface"] == "foobar"
    assert cfg["virtualbox"]["honeyd"]["label"] == "honeyd"
    assert cfg["virtualbox"]["honeyd"]["platform"] == "linux"
    assert cfg["virtualbox"]["honeyd"]["ip"] == "192.168.56.102"
    assert cfg["virtualbox"]["honeyd"]["tags"] == "service, honeyd"
    assert cfg["virtualbox"]["honeyd"]["options"] == "nictrace noagent"
    assert cfg["vmware"]["vmware"]["interface"] == "virbr0"
    assert cfg["vpn"]["vpn"]["enabled"] is False
    assert cfg["vpn"]["vpn"]["vpns"] == "vpn0"
    assert cfg["vpn"]["vpn0"]["name"] == "vpn0"
    assert cfg["vpn"]["vpn0"]["description"] == "Spain, Europe"
    assert cfg["vpn"]["vpn0"]["interface"] == "tun0"
    assert cfg["vsphere"]["vsphere"]["host"] == "10.0.0.1"
    assert cfg["vsphere"]["vsphere"]["port"] == 443
    assert cfg["vsphere"]["vsphere"]["user"] == "username_goes_here"
    assert cfg["vsphere"]["vsphere"]["pwd"] == "password_goes_here"
    assert cfg["vsphere"]["vsphere"]["interface"] == "eth0"
    assert cfg["vsphere"]["analysis1"]["label"] == "cuckoo1"
    assert cfg["vsphere"]["analysis1"]["platform"] == "windows"
    assert cfg["vsphere"]["analysis1"]["snapshot"] == "cuckoo_ready_running"
    assert cfg["vsphere"]["analysis1"]["ip"] == "192.168.1.1"
    assert cfg["xenserver"]["xenserver"]["interface"] == "virbr0"

def test_migration_20c1_20c2():
    set_cwd(tempfile.mkdtemp())
    Folders.create(cwd(), "conf")
    Files.create(cwd("conf"), "auxiliary.conf", """
[sniffer]
interface = foobar
""")
    Files.create(cwd("conf"), "cuckoo.conf", """
[routing]
internet = none
[resultserver]
port = 2042
[timeouts]
critical = 600
""")
    Files.create(cwd("conf"), "processing.conf", """
[network]
enabled = yes
[procmemory]
idapro = no
[static]
enabled = yes
""")
    Files.create(cwd("conf"), "reporting.conf", """
[jsondump]
enabled = yes
""")
    Files.create(cwd("conf"), "vpn.conf", """
[vpn]
enabled = yes
vpns = vpn0
[vpn0]
interface = hehe
""")
    cfg = Config.from_confdir(cwd("conf"), loose=True)
    cfg = migrate(cfg, "2.0-rc1", "2.0-rc2")
    assert cfg["auxiliary"]["reboot"]["enabled"] is True
    assert cfg["cuckoo"]["routing"]["rt_table"] == "main"
    assert cfg["cuckoo"]["routing"]["auto_rt"] is True
    assert cfg["cuckoo"]["resultserver"]["force_port"] is False
    assert cfg["cuckoo"]["timeouts"]["critical"] == 60
    assert cfg["processing"]["misp"]["enabled"] is False
    assert cfg["processing"]["misp"]["url"] is None
    assert cfg["processing"]["misp"]["apikey"] is None
    assert cfg["processing"]["misp"]["maxioc"] == 100
    assert cfg["processing"]["network"]["whitelist-dns"] is False
    assert cfg["processing"]["network"]["allowed-dns"] is None
    assert cfg["processing"]["procmemory"]["extract_img"] is True
    assert cfg["processing"]["procmemory"]["dump_delete"] is False
    assert cfg["processing"]["static"]["pdf_timeout"] == 60
    assert cfg["processing"]["irma"]["enabled"] is False
    assert cfg["processing"]["irma"]["timeout"] == 60
    assert cfg["processing"]["irma"]["scan"] is False
    assert cfg["processing"]["irma"]["force"] is False
    assert cfg["reporting"]["elasticsearch"]["enabled"] is False
    assert cfg["reporting"]["elasticsearch"]["hosts"] == "127.0.0.1"
    assert cfg["reporting"]["elasticsearch"]["calls"] is False
    assert cfg["reporting"]["notification"]["enabled"] is False
    assert cfg["reporting"]["notification"]["url"] is None
    assert cfg["reporting"]["notification"]["identifier"] is None
    assert cfg["reporting"]["mattermost"]["enabled"] is False
    assert cfg["reporting"]["mattermost"]["username"] == "cuckoo"
    assert cfg["vpn"]["vpn"]["enabled"] == "yes"
    assert cfg["vpn"]["vpn0"]["rt_table"] == "hehe"

def test_migration_20c2_200():
    set_cwd(tempfile.mkdtemp())
    Folders.create(cwd(), "conf")
    Files.create(cwd("conf"), "auxiliary.conf", """
[mitm]
script = data/mitm.py
[sniffer]
tcpdump = foobar
""")
    Files.create(cwd("conf"), "cuckoo.conf", """
[cuckoo]
tmppath = /tmp
freespace = 64
[routing]
route = foo
internet = bar
rt_table = main
auto_rt = no
[resultserver]
upload_max_size = 10485760
[processing]
analysis_size_limit = 104857600
""")
    Files.create(cwd("conf"), "processing.conf", """
[network]
whitelist-dns = yes
allowed-dns = 8.8.8.8
[procmemory]
enabled = yes
extract_img = yes
[virustotal]
enabled = yes
key = a0283a2c3d55728300d064874239b5346fb991317e8449fe43c902879d758088
""")
    Files.create(cwd("conf"), "qemu.conf", """
[qemu]
machines = vm1, vm2
[vm1]
label = vm1
kernel_path = kernelpath
[vm2]
label = vm2
kernel_path = anotherpath
""")
    Files.create(cwd("conf"), "reporting.conf", """
[elasticsearch]
enabled = no
hosts = 127.0.0.1, 127.0.0.2
[mattermost]
show-virustotal = no
show-signatures = yes
show-urls = no
hash-filename = yes
[moloch]
enabled = no
[mongodb]
enables = yes
[notification]
enabled = no
[jsondump]
indent = 8
encoding = utf8
[reporthtml]
enabled = yes
""")
    Files.create(cwd("conf"), "vpn.conf", """
[vpn]
enabled = yes
vpns = vpn0,vpn1
[vpn0]
name = vpn0
description = foobar
interface = tun42
rt_table = tun42
[vpn1]
name = vpn1
description = internet
interface = wow
rt_table = internet
""")
    Files.create(cwd("conf"), "vsphere.conf", """
[vsphere]
interface = eth0
""")
    cfg = Config.from_confdir(cwd("conf"), loose=True)
    assert "vpn" in cfg
    assert "whitelist-dns" in cfg["processing"]["network"]
    assert "allowed-dns" in cfg["processing"]["network"]
    cfg = migrate(cfg, "2.0-rc2", "2.0.0")
    assert cfg["auxiliary"]["mitm"]["script"] == "mitm.py"
    assert cfg["cuckoo"]["cuckoo"]["freespace"] == 1024
    assert cfg["cuckoo"]["cuckoo"]["tmppath"] is None
    assert cfg["cuckoo"]["feedback"]["enabled"] is False
    assert cfg["cuckoo"]["feedback"]["name"] is None
    assert cfg["cuckoo"]["feedback"]["company"] is None
    assert cfg["cuckoo"]["feedback"]["email"] is None
    assert cfg["cuckoo"]["processing"]["analysis_size_limit"] == 128*1024*1024
    assert cfg["cuckoo"]["resultserver"]["upload_max_size"] == 128*1024*1024
    assert "whitelist-dns" not in cfg["processing"]["network"]
    assert "allowed-dns" not in cfg["processing"]["network"]
    assert cfg["processing"]["network"]["whitelist_dns"] is True
    assert cfg["processing"]["procmemory"]["extract_dll"] is False
    assert cfg["processing"]["network"]["allowed_dns"] == "8.8.8.8"
    assert cfg["processing"]["virustotal"]["enabled"] is False
    assert cfg["reporting"]["elasticsearch"]["hosts"] == [
        "127.0.0.1", "127.0.0.2"
    ]
    assert cfg["qemu"]["vm1"]["kernel"] == "kernelpath"
    assert cfg["qemu"]["vm2"]["kernel"] == "anotherpath"
    assert cfg["reporting"]["jsondump"]["indent"] == 8
    assert "encoding" not in cfg["reporting"]["jsondump"]
    assert cfg["reporting"]["notification"]["url"] is None
    assert cfg["reporting"]["mattermost"]["show_virustotal"] is False
    assert cfg["reporting"]["mattermost"]["show_signatures"] is True
    assert cfg["reporting"]["mattermost"]["show_urls"] is False
    assert cfg["reporting"]["mattermost"]["hash_filename"] is True
    assert cfg["reporting"]["mattermost"]["hash_url"] is False
    assert cfg["reporting"]["moloch"]["insecure"] is False
    assert cfg["reporting"]["mongodb"]["username"] is None
    assert cfg["reporting"]["mongodb"]["password"] is None
    assert cfg["reporting"]["singlefile"]["enabled"] is True
    assert cfg["reporting"]["singlefile"]["html"] is True
    assert cfg["reporting"]["singlefile"]["pdf"] is False
    assert "reporthtml" not in cfg["reporting"]
    assert cfg["routing"]["routing"]["route"] == "foo"
    assert cfg["routing"]["routing"]["internet"] == "bar"
    assert cfg["routing"]["routing"]["rt_table"] == "main"
    assert cfg["routing"]["routing"]["auto_rt"] is False
    assert cfg["routing"]["routing"]["drop"] is False
    assert cfg["routing"]["inetsim"]["enabled"] is False
    assert cfg["routing"]["inetsim"]["server"] == "192.168.56.1"
    assert cfg["routing"]["tor"]["enabled"] is False
    assert cfg["routing"]["tor"]["dnsport"] == 5353
    assert cfg["routing"]["tor"]["proxyport"] == 9040
    assert cfg["routing"]["vpn"]["enabled"] is True
    assert cfg["routing"]["vpn"]["vpns"] == ["vpn0", "vpn1"]
    assert cfg["routing"]["vpn0"]["name"] == "vpn0"
    assert cfg["routing"]["vpn0"]["description"] == "foobar"
    assert cfg["routing"]["vpn0"]["interface"] == "tun42"
    assert cfg["routing"]["vpn0"]["rt_table"] == "tun42"
    assert cfg["routing"]["vpn1"]["name"] == "vpn1"
    assert cfg["routing"]["vpn1"]["description"] == "internet"
    assert cfg["routing"]["vpn1"]["interface"] == "wow"
    assert cfg["routing"]["vpn1"]["rt_table"] == "internet"
    assert cfg["vsphere"]["vsphere"]["unverified_ssl"] is False
    assert "vpn" not in cfg

def test_migration_200_201():
    set_cwd(tempfile.mkdtemp())
    Folders.create(cwd(), "conf")
    Files.create(cwd("conf"), "memory.conf", """
[mask]
pid_generic =
""")
    cfg = Config.from_confdir(cwd("conf"), loose=True)
    cfg = migrate(cfg, "2.0.0", "2.0.1")
    assert cfg["memory"]["mask"]["pid_generic"] == []

def test_migration_201_202():
    set_cwd(tempfile.mkdtemp())
    Folders.create(cwd(), "conf")
    Files.create(cwd("conf"), "virtualbox.conf", """
[virtualbox]
machines = cuckoo1, cuckoo2
[cuckoo1]
platform = windows
[cuckoo2]
platform = windows
""")
    # Except for virtualbox.
    machineries = (
        "avd", "esx", "kvm", "physical", "qemu",
        "vmware", "vsphere", "xenserver",
    )
    for machinery in machineries:
        Files.create(
            cwd("conf"), "%s.conf" % machinery,
            "[%s]\nmachines =" % machinery
        )
    cfg = Config.from_confdir(cwd("conf"), loose=True)
    cfg = migrate(cfg, "2.0.1", "2.0.2")
    assert cfg["virtualbox"]["cuckoo1"]["osprofile"] is None
    assert cfg["virtualbox"]["cuckoo2"]["osprofile"] is None

def test_migration_203_204():
    set_cwd(tempfile.mkdtemp())
    Folders.create(cwd(), "conf")
    Files.create(cwd("conf"), "processing.conf", """
[dumptls]
enabled = on
""")
    Files.create(cwd("conf"), "qemu.conf", """
[qemu]
machines = ubuntu32, ubuntu64
[ubuntu32]
arch = x86
[ubuntu64]
arch = x64
    """)
    cfg = Config.from_confdir(cwd("conf"), loose=True)
    cfg = migrate(cfg, "2.0.3", "2.0.4")
    assert cfg["processing"]["extracted"]["enabled"] is True
    # Except for qemu.
    machineries = (
        "avd", "esx", "kvm", "physical", "virtualbox",
        "vmware", "vsphere", "xenserver",
    )
    for machinery in machineries:
        Files.create(
            cwd("conf"), "%s.conf" % machinery, "[%s]\nmachines =" % machinery
        )
    assert cfg["qemu"]["ubuntu32"]["enable_kvm"] is False
    assert cfg["qemu"]["ubuntu32"]["snapshot"] is None

def test_migration_204_205():
    set_cwd(tempfile.mkdtemp())
    Folders.create(cwd(), "conf")
    Files.create(cwd("conf"), "auxiliary.conf", """
[mitm]
script = mitm.py
""")
    cfg = Config.from_confdir(cwd("conf"), loose=True)
    cfg = migrate(cfg, "2.0.4", "2.0.5")

    assert cfg["auxiliary"]["mitm"]["script"] == "stuff/mitm.py"

def test_migration_205_206():
    set_cwd(tempfile.mkdtemp())
    Folders.create(cwd(), "conf")

    Files.create(cwd("conf"), "cuckoo.conf", """
[database]
    """)
    Files.create(cwd("conf"), "virtualbox.conf", """
[virtualbox]
machines = vbox1
[vbox1]
mode = headless
    """)
    cfg = Config.from_confdir(cwd("conf"), loose=True)
    cfg = migrate(cfg, "2.0.5", "2.0.6")

    assert cfg["cuckoo"]["remotecontrol"]["enabled"] == False
    assert cfg["cuckoo"]["remotecontrol"]["guacd_host"] == "localhost"
    assert cfg["cuckoo"]["remotecontrol"]["guacd_port"] == 4822

    assert cfg["virtualbox"]["controlports"] == "5000-5050"

class FullMigration(object):
    DIRPATH = None
    VERSION = None

    def test_full_migration(self):
        cfg = Config.from_confdir(self.DIRPATH, loose=True)
        cfg = migrate(cfg, self.VERSION)

        # Ensure that all values exist and that have the correct types.
        for filename, sections in Config.configuration.items():
            assert filename in cfg
            for section, entries in sections.items():
                # We check machines and VPNs manually later on.
                if section == "*" or section == "__star__":
                    continue

                assert section in cfg[filename]
                for key, value in entries.items():
                    if key not in cfg[filename][section]:
                        continue
                    actual_value = cfg[filename][section][key]
                    assert actual_value == value.parse(actual_value)

        machineries = (
            "avd", "esx", "kvm", "physical", "qemu", "virtualbox",
            "vmware", "vsphere", "xenserver",
        )

        for machinery in machineries:
            for machine in cfg[machinery][machinery]["machines"]:
                assert machine in cfg[machinery]
                type_ = Config.configuration[machinery]["*"]
                if isinstance(type_, (tuple, list)):
                    type_ = type_[0]

                for key, value in cfg[machinery][machine].items():
                    assert value == type_[key].parse(value)

        for vpn in cfg["routing"]["vpn"]["vpns"]:
            assert vpn in cfg["routing"]
            type_ = Config.configuration["routing"]["*"]
            if isinstance(type_, (tuple, list)):
                type_ = type_[0]

            for key, value in cfg["routing"][vpn].items():
                assert value == type_[key].parse(value)

    def test_write_configuration(self):
        set_cwd(tempfile.mkdtemp())
        cfg = Config.from_confdir(self.DIRPATH, loose=True)
        cfg = migrate(cfg, self.VERSION)
        cuckoo_create(cfg=cfg)

class TestFullMigration040(FullMigration):
    DIRPATH = "tests/files/conf/040_plain"
    VERSION = "0.4"

class TestFullMigration110(FullMigration):
    DIRPATH = "tests/files/conf/110_plain"
    VERSION = "1.1"

class TestFullMigration120(FullMigration):
    DIRPATH = "tests/files/conf/120_plain"
    VERSION = "1.2"

class TestFullMigration120Production(FullMigration):
    DIRPATH = "tests/files/conf/120_5vms"
    VERSION = "1.2"

    def test_vms_count(self):
        cfg = Config.from_confdir(self.DIRPATH, loose=True)
        cfg = migrate(cfg, self.VERSION)
        assert cfg["virtualbox"]["virtualbox"]["mode"] == "headless"
        assert len(cfg["virtualbox"]["virtualbox"]["machines"]) == 5
        assert cfg["virtualbox"]["cuckoo3"]["ip"] == "192.168.56.103"
        assert cfg["virtualbox"]["cuckoo3"]["osprofile"] is None

class TestFullMigration20c1(FullMigration):
    DIRPATH = "tests/files/conf/20c1_plain"
    VERSION = "2.0-rc1"

class TestFullMigration20c2(FullMigration):
    DIRPATH = "tests/files/conf/20c2_plain"
    VERSION = "2.0-rc2"

def test_cast():
    assert cast("cuckoo:cuckoo:version_check", "1") is True
    assert cast("cuckoo:cuckoo:version_check", "0") is False
    assert cast("cuckoo:cuckoo:version_check", "on") is True
    assert cast("cuckoo:cuckoo:version_check", "off") is False
    assert cast("cuckoo:cuckoo:version_check", "yes") is True
    assert cast("cuckoo:cuckoo:version_check", "no") is False

    assert cast("cuckoo:cuckoo:machinery", "virtualbox") == "virtualbox"
    assert cast("cuckoo:cuckoo:machinery", "1") == "1"

    assert cast("cuckoo:cuckoo:freespace", "1234") == 1234

    assert cast("virtualbox:cuckoo1:options", "") == []
    assert cast("virtualbox:cuckoo1:options", "a b c") == ["a", "b", "c"]
    assert cast("virtualbox:cuckoo1:options", "a, b c") == ["a", "b", "c"]

    assert cast("memory:mask:pid_generic", "") == []
    assert cast("memory:mask:pid_generic", "1, 2, 3") == ["1", "2", "3"]

def test_list_split():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    assert config("virtualbox:cuckoo1:options") == []

    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "virtualbox": {
            "cuckoo1": {
                "options": ["noagent", "nictrace"],
            },
        },
    })
    assert config("virtualbox:cuckoo1:options") == [
        "noagent", "nictrace",
    ]

@mock.patch("cuckoo.common.config.log")
def test_list_default_none(p):
    List(String, None, ",")
    p.error.assert_not_called()

def test_path():
    assert Path(allow_empty=True).check("") is True
    assert Path(allow_empty=True).check(None) is True

class TestKvConf(object):
    def test_success(self):
        filepath = Files.temp_put("""
        cuckoo.cuckoo.version_check = off
        auxiliary.sniffer.enabled = no
        """)
        assert read_kv_conf(filepath) == {
            "cuckoo": {
                "cuckoo": {
                    "version_check": False,
                },
            },
            "auxiliary": {
                "sniffer": {
                    "enabled": False,
                },
            },
        }

    def test_star_existing(self):
        filepath = Files.temp_put("""
        virtualbox.cuckoo1.resultserver_port = 1234
        """)
        assert read_kv_conf(filepath) == {
            "virtualbox": {
                "cuckoo1": {
                    "resultserver_port": 1234,
                },
            },
        }

    def test_star_new(self):
        filepath = Files.temp_put("""
        virtualbox.virtualbox.machines = cuckoo2, cuckoo3
        virtualbox.cuckoo2.ip = 192.168.56.102
        virtualbox.cuckoo3.ip = 192.168.56.103
        virtualbox.notexistingvm.ip = 1.2.3.4
        """)
        assert read_kv_conf(filepath) == {
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
        }

    def test_fail1(self):
        filepath = Files.temp_put("a = b")
        with pytest.raises(CuckooConfigurationError) as e:
            read_kv_conf(filepath)
        e.match("Invalid configuration entry")

    def test_fail2(self):
        filepath = Files.temp_put("a.b.c : d")
        with pytest.raises(CuckooConfigurationError) as e:
            read_kv_conf(filepath)
        e.match("missing .* character")

    def test_fail3(self):
        filepath = Files.temp_put("cuckoo.cuckoo.version_check = foo")
        with pytest.raises(CuckooConfigurationError) as e:
            read_kv_conf(filepath)
        e.match("Invalid flat configuration entry")

def test_config2_default():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    assert config2("processing", "suricata") == {
        "enabled": False, "eve_log": "eve.json", "files_dir": "files",
        "socket": None, "suricata": "/usr/bin/suricata",
        "conf": "/etc/suricata/suricata.yaml", "files_log": "files-json.log",
    }

def test_config2_custom():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "processing": {
            "virustotal": {
                "key": "thisisthekey",
            },
        },
    })
    assert config2("processing", "virustotal") == {
        "enabled": False,
        "key": "thisisthekey",
        "timeout": 60,
        "scan": False,
    }

def test_config2_vpns():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "routing": {
            "vpn": {
                "vpns": [
                    "a", "b",
                ],
            },
            "a": {
                "name": "name_a",
                "description": "desc_a",
            },
            "b": {
                "name": "name_b",
                "description": "desc_b",
            },
        },
    })
    assert config2("routing", "vpn") == {
        "enabled": False,
        "vpns": [
            "a", "b",
        ],
    }
    assert config2("routing", "a") == {
        "__section__": None,
        "name": "name_a",
        "description": "desc_a",
        "interface": None,
        "rt_table": None,
    }
    with pytest.raises(CuckooConfigurationError) as e:
        config2("routing", "c")
    e.match("No such configuration section exists")

    assert config2("routing", "a").name == "name_a"
    assert config2("routing", "a").interface is None

def test_config2_liststar():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    assert config2("qemu", "vm1").interface == "qemubr"

@mock.patch("cuckoo.common.config.log")
def test_no_superfluous_conf(p):
    """Tests that upon CWD creation no superfluous configuration values are
    writted out (which may happen after a configuration migration)."""
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    Config.from_confdir(cwd("conf"))
    p.error.assert_not_called()

def test_faq():
    assert faq("hehe").startswith("http")
    assert faq("hehe").endswith("#hehe")

def test_incomplete_envvar():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "cuckoo": {
            "database": {
                "connection": "%(",
            },
        },
    })

    # Clear cache.
    for key in _cache.keys():
        del _cache[key]

    with pytest.raises(CuckooConfigurationError) as e:
        config("cuckoo:database:connection")
    e.match("One of the fields")
