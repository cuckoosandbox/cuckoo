# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ConfigParser
import os
import logging
import click

from cuckoo.common.exceptions import CuckooConfigurationError
from cuckoo.common.objects import Dictionary
from cuckoo.common.utils import parse_bool
from cuckoo.misc import cwd

log = logging.getLogger(__name__)

_cache = {}

class Type(object):
    """Base Class for Type Definitions"""

    def __init__(self, default=None, required=True, sanitize=False,
                 allow_empty=False):
        self.required = required
        self.sanitize = sanitize
        self.allow_empty = allow_empty
        self.default = self.parse(default)

    def parse(self, value):
        """Parse a raw input value."""

    def check(self, value):
        """Checks the type of the value."""

    def emit(self, value):
        """String-readable version of this object"""

class Int(Type):
    """Integer Type Definition class."""

    def parse(self, value):
        if isinstance(value, (int, long)):
            return value

        if isinstance(value, basestring) and value.isdigit():
            return int(value)

    def check(self, value):
        if self.allow_empty and not value:
            return True

        try:
            click.INT(value)
            return True
        except:
            return False

    def emit(self, value):
        return "%d" % value if value is not None else ""

class String(Type):
    """String Type Definition class."""

    def parse(self, value):
        return value.strip() if value else None

    def check(self, value):
        if self.allow_empty and not value:
            return True

        return isinstance(value, basestring)

    def emit(self, value):
        return value or ""

class Path(String):
    """Path Type Definition class."""

    def __init__(self, default=None, exists=False, writable=False,
                 readable=False, required=True, allow_empty=False,
                 sanitize=False):
        self.exists = exists
        self.writable = writable
        self.readable = readable
        super(Path, self).__init__(default, required, sanitize, allow_empty)

    def parse(self, value):
        if self.allow_empty and not value:
            return

        try:
            c = click.Path(
                exists=self.exists,
                writable=self.writable,
                readable=self.readable
            )
            return c.convert(value, None, None)
        except Exception:
            return value

    def check(self, value):
        if self.allow_empty and not value:
            return True

        try:
            c = click.Path(
                exists=self.exists,
                writable=self.writable,
                readable=self.readable
            )
            c.convert(value, None, None)
            return True
        except:
            return False

    def emit(self, value):
        return value or ""

class Boolean(Type):
    """Boolean Type Definition class."""

    def parse(self, value):
        try:
            return parse_bool(value)
        except:
            log.error("Incorrect Boolean %s", value)

    def check(self, value):
        try:
            parse_bool(value)
            return True
        except:
            return False

    def emit(self, value):
        return "yes" if value else "no"

class UUID(Type):
    """UUID Type Definition class."""

    def parse(self, value):
        try:
            c = click.UUID(value)
            return str(c)
        except:
            log.error("Incorrect UUID %s", value)

    def check(self, value):
        """Checks if the value is of type UUID."""
        try:
            click.UUID(value)
            return True
        except:
            return False

    def emit(self, value):
        return value

class List(Type):
    """List Type Definition class."""

    def __init__(self, subclass, default, sep=",", strip=False):
        self.subclass = subclass
        self.sep = sep
        self.strip = strip
        super(List, self).__init__(default)

    def parse(self, value):
        try:
            ret = []

            if isinstance(value, (tuple, list)):
                for entry in value:
                    ret.append(self.subclass().parse(entry))
                return ret

            for entry in value.split(self.sep):
                if self.strip:
                    entry = entry.strip()
                    if not entry:
                        continue

                ret.append(self.subclass().parse(entry))
            return ret
        except:
            log.error("Incorrect list: %s", value)

    def check(self, value):
        try:
            value.split(self.sep)
            return True
        except:
            return False

    def emit(self, value):
        return self.sep.join(value)

class Config(object):
    """Configuration file parser."""

    configuration = {
        "cuckoo": {
            "cuckoo": {
                "version_check": Boolean(True),
                "delete_original": Boolean(False),
                "delete_bin_copy": Boolean(False),
                "machinery": String("virtualbox"),
                "memory_dump": Boolean(False),
                "terminate_processes": Boolean(False),
                "reschedule": Boolean(False),
                "process_results": Boolean(True),
                "max_analysis_count": Int(0),
                "max_machines_count": Int(0),
                "max_vmstartup_count": Int(10),
                "freespace": Int(64),
                "tmppath": Path(
                    exists=True, writable=True, readable=False,
                    allow_empty=True
                ),
                "rooter": Path(
                    "/tmp/cuckoo-rooter",
                    exists=False, writable=False, readable=True
                ),
            },
            "feedback": {
                "enabled": Boolean(False),
                "name": String(),
                "company": String(),
                "email": String(),
            },
            "resultserver": {
                "ip": String("192.168.56.1"),
                "port": Int(2042),
                "force_port": Boolean(False),
                "upload_max_size": Int(10485760),
            },
            "processing": {
                "analysis_size_limit": Int(104857600),
                "resolve_dns": Boolean(True),
                "sort_pcap": Boolean(True),
            },
            "database": {
                "connection": String(sanitize=True),
                "timeout": Int(allow_empty=True),
            },
            "timeouts": {
                "default": Int(120),
                "critical": Int(60),
                "vm_state": Int(60),
            },
        },
        "virtualbox": {
            "virtualbox": {
                "mode": String("headless"),
                "path": Path(
                    "/usr/bin/VBoxManage",
                    exists=True, writable=False, readable=True
                ),
                "interface": String("vboxnet0"),
                "machines": List(String, "cuckoo1"),
            },
            "*": {
                "__section__": "cuckoo1",
                "label": String("cuckoo1"),
                "platform": String("windows"),
                "ip": String("192.168.56.101"),
                "snapshot": String(),
                "interface": String(),
                "resultserver_ip": String(),
                "resultserver_port": Int(),
                "tags": String(),
                "options": String(),
            },
        },
        "auxiliary": {
            "sniffer": {
                "enabled": Boolean(True),
                "tcpdump": Path(
                    "/usr/sbin/tcpdump",
                    exists=True, writable=False, readable=True
                ),
                "bpf": String(),
            },
            "mitm": {
                "enabled": Boolean(False),
                "mitmdump": Path(
                    "/usr/local/bin/mitmdump",
                    exists=False, writable=False, readable=True
                ),
                "port_base": Int(50000),
                "script": Path(
                    "mitm.py",
                    exists=False, writable=False, readable=True
                ),
                "certificate": Path(
                    "bin/cert.p12",
                    exists=False, writable=False, readable=True
                ),
            },
            "services": {
                "enabled": Boolean(False),
                "services": String("honeyd"),
                "timeout": Int(0),
            },
            "reboot": {
                "enabled": Boolean(True),
            },
        },
        "avd": {
            "avd": {
                "mode": String("headless"),
                "emulator_path": Path(
                    "/home/cuckoo/android-sdk-linux/tools/emulator",
                    exists=True, writable=False, readable=True
                ),
                "adb_path": Path(
                    "/home/cuckoo/android-sdk-linux/platform-tools/adb",
                    exists=True, writable=False, readable=True
                ),
                "avd_path": Path(
                    "/home/cuckoo/.android/avd",
                    exists=True, writable=False, readable=True
                ),
                "reference_machine": String("cuckoo-bird"),
                "machines": List(String, "cuckoo1"),
            },
            "*": {
                "__section__": "cuckoo1",
                "label": String("cuckoo1"),
                "platform": String("android"),
                "ip": String("127.0.0.1"),
                "emulator_port": Int(5554),
                "resultserver_ip": String("10.0.2.2"),
                "resultserver_port": Int(2042),
            },
        },
        "esx": {
            "esx": {
                "dsn": String("esx://127.0.0.1/?no_verify=1"),
                "username": String("username_goes_here"),
                "password": String("password_goes_here", sanitize=True),
                "machines": List(String, "analysis1"),
                "interface": String("eth0"),
            },
            "*": {
                "__section__": "analysis1",
                "label": String("cuckoo1"),
                "platform": String("windows"),
                "ip": String("192.168.122.105"),
                "snapshot": String("clean_snapshot"),
                "interface": String(),
                "resultserver_ip": String(),
                "resultserver_port": Int(),
                "tags": String(),
            },
        },
        "kvm": {
            "kvm": {
                "interface": String("virbr0"),
                "machines": List(String, "cuckoo1"),
            },
            "*": {
                "__section__": "cuckoo1",
                "label": String("cuckoo1"),
                "platform": String("windows"),
                "ip": String("192.168.122.105"),
                "snapshot": String(),
                "interface": String(),
                "resultserver_ip": String(),
                "resultserver_port": Int(),
                "tags": String(),
            },
        },
        "memory": {
            "basic": {
                "guest_profile": String("WinXPSP2x86"),
                "delete_memdump": Boolean(False),
            },
            "malfind": {
                "enabled": Boolean(True),
                "filter": Boolean(True),
            },
            "apihooks": {
                "enabled": Boolean(False),
                "filter": Boolean(True),
            },
            "pslist": {
                "enabled": Boolean(True),
                "filter": Boolean(False),
            },
            "psxview": {
                "enabled": Boolean(True),
                "filter": Boolean(False),
            },
            "callbacks": {
                "enabled": Boolean(True),
                "filter": Boolean(False),
            },
            "idt": {
                "enabled": Boolean(True),
                "filter": Boolean(False),
            },
            "timers": {
                "enabled": Boolean(True),
                "filter": Boolean(False),
            },
            "messagehooks": {
                "enabled": Boolean(False),
                "filter": Boolean(False),
            },
            "getsids": {
                "enabled": Boolean(True),
                "filter": Boolean(False),
            },
            "privs": {
                "enabled": Boolean(True),
                "filter": Boolean(False),
            },
            "dlllist": {
                "enabled": Boolean(True),
                "filter": Boolean(True),
            },
            "handles": {
                "enabled": Boolean(True),
                "filter": Boolean(True),
            },
            "ldrmodules": {
                "enabled": Boolean(True),
                "filter": Boolean(True),
            },
            "mutantscan": {
                "enabled": Boolean(True),
                "filter": Boolean(True),
            },
            "devicetree": {
                "enabled": Boolean(True),
                "filter": Boolean(True),
            },
            "svcscan": {
                "enabled": Boolean(True),
                "filter": Boolean(True),
            },
            "modscan": {
                "enabled": Boolean(True),
                "filter": Boolean(True),
            },
            "yarascan": {
                "enabled": Boolean(True),
                "filter": Boolean(True),
            },
            "ssdt": {
                "enabled": Boolean(True),
                "filter": Boolean(True),
            },
            "gdt": {
                "enabled": Boolean(True),
                "filter": Boolean(True),
            },
            "sockscan": {
                "enabled": Boolean(True),
                "filter": Boolean(False),
            },
            "netscan": {
                "enabled": Boolean(True),
                "filter": Boolean(False),
            },
            "mask": {
                "enabled": Boolean(False),
                "pid_generic": String(),
            },
        },
        "physical": {
            "physical": {
                "machines": List(String, "physical1"),
                "user": String("username"),
                "password": String("password", sanitize=True),
                "interface": String("eth0"),
            },
            "fog": {
                "hostname": String("none"),
                "username": String("fog"),
                "password": String("password", sanitize=True),
            },
            "*": {
                "__section__": "physical1",
                "label": String("physical1"),
                "platform": String("windows"),
                "ip": String("192.168.56.101"),
            },
        },
        "processing": {
            "analysisinfo": {
                "enabled": Boolean(True),
            },
            "apkinfo": {
                "enabled": Boolean(False),
                "decompilation_threshold": Int(5000000),
            },
            "baseline": {
                "enabled": Boolean(False),
            },
            "behavior": {
                "enabled": Boolean(True),
            },
            "buffer": {
                "enabled": Boolean(True),
            },
            "debug": {
                "enabled": Boolean(True),
            },
            "droidmon": {
                "enabled": Boolean(False),
            },
            "dropped": {
                "enabled": Boolean(True),
            },
            "dumptls": {
                "enabled": Boolean(True),
            },
            "googleplay": {
                "enabled": Boolean(False),
                "android_id": String(),
                "google_login": String(),
                "google_password": String(sanitize=True),
            },
            "memory": {
                "enabled": Boolean(False),
            },
            "misp": {
                "enabled": Boolean(False),
                "url": String(),
                "apikey": String(sanitize=True),
                "maxioc": Int(100),
            },
            "network": {
                "enabled": Boolean(True),
                "whitelist_dns": Boolean(False),
                "allowed_dns": String(),
            },
            "procmemory": {
                "enabled": Boolean(True),
                "idapro": Boolean(False),
                "extract_img": Boolean(True),
                "dump_delete": Boolean(False),
            },
            "procmon": {
                "enabled": Boolean(True),
            },
            "screenshots": {
                "enabled": Boolean(True),
                "tesseract": String("no"),
            },
            "snort": {
                "enabled": Boolean(False),
                "snort": Path(
                    "/usr/local/bin/snort",
                    exists=False, writable=False, readable=True
                ),
                "conf": Path(
                    "/etc/snort/snort.conf",
                    exists=False, writable=False, readable=True
                ),
            },
            "static": {
                "enabled": Boolean(True),
                "pdf_timeout": Int(60),
            },
            "strings": {
                "enabled": Boolean(True),
            },
            "suricata": {
                "enabled": Boolean(False),
                "suricata": Path(
                    "/usr/bin/suricata",
                    exists=True, writable=False, readable=True
                ),
                "conf": Path(
                    "/etc/suricata/suricata.yaml",
                    exists=True, writable=False, readable=True
                ),
                "eve_log": Path(
                    "eve.json",
                    exists=False, writable=True, readable=False
                ),
                "files_log": Path(
                    "files-json.log",
                    exists=False, writable=True, readable=False
                ),
                "files_dir": Path(
                    "files",
                    exists=False, writable=False, readable=True
                ),
                "socket": Path(
                    exists=True, writable=False, readable=True,
                    allow_empty=True
                ),
            },
            "targetinfo": {
                "enabled": Boolean(True),
            },
            "virustotal": {
                "enabled": Boolean(True),
                "timeout": Int(60),
                "scan": Boolean(False),
                "key": String("a0283a2c3d55728300d064874239b5346fb991317e8449fe43c902879d758088", sanitize=True),
            },
            "irma": {
                "enabled": Boolean(False),
                "timeout": Int(60),
                "scan": Boolean(False),
                "force": Boolean(False),
                "url": String(),
            },
        },
        "qemu": {
            "qemu": {
                "path": Path(
                    "/usr/bin/qemu-system-x86_64",
                    exists=True, writable=False, readable=True
                ),
                "interface": String("qemubr"),
                "machines": List(String, "vm1,vm2"),
            },
            "*": [
                {
                    "__section__": "vm1",
                    "label": String("vm1"),
                    "image": Path(
                        "/home/rep/vms/qvm_wheezy64_1.qcow2",
                        exists=True, writable=False, readable=True
                    ),
                    "arch": String(),
                    "platform": String("linux"),
                    "ip": String("192.168.55.2"),
                    "interface": String("qemubr"),
                    "resultserver_ip": String("192.168.55.1"),
                    "resultserver_port": Int(),
                    "tags": String("debian_wheezy,64_bit"),
                    "kernel_path": String(),
                }, {
                    "__section__": "vm2",
                    "label": String("vm2"),
                    "image": Path(
                        "/home/rep/vms/qvm_wheezy64_1.qcow2",
                        exists=True, writable=False, readable=True
                    ),
                    "arch": String("mipsel"),
                    "platform": String("linux"),
                    "ip": String("192.168.55.3"),
                    "interface": String("qemubr"),
                    "resultserver_ip": String("192.168.55.1"),
                    "resultserver_port": Int(),
                    "tags": String("debian_wheezy,mipsel"),
                    "kernel_path": String(
                        "{imagepath}/vmlinux-3.16.0-4-4kc-malta-mipsel"
                    ),
                },
            ],
        },
        "reporting": {
            "jsondump": {
                "enabled": Boolean(True),
                "indent": Int(4),
                "encoding": String("latin-1"),
                "calls": Boolean(True),
            },
            "reporthtml": {
                "enabled": Boolean(False),
            },
            "misp": {
                "enabled": Boolean(False),
                "url": String(),
                "apikey": String(sanitize=True),
                "mode": String("maldoc ipaddr"),
            },
            "mongodb": {
                "enabled": Boolean(False),
                "host": String("127.0.0.1"),
                "port": Int(27017),
                "db": String("cuckoo"),
                "store_memdump": Boolean(True),
                "paginate": Int(100),
            },
            "elasticsearch": {
                "enabled": Boolean(False),
                "hosts": String("127.0.0.1"),
                "calls": Boolean(False),
                "index": String(),
                "index_time_pattern": String(),
                "cuckoo_node": String(),
            },
            "moloch": {
                "enabled": Boolean(False),
                "host": String(),
                "moloch_capture": Path(
                    "/data/moloch/bin/moloch-capture",
                    exists=True, writable=False, readable=True
                ),
                "conf": Path(
                    "/data/moloch/etc/config.ini",
                    exists=True, writable=False, readable=True
                ),
                "instance": String("cuckoo"),
            },
            "notification": {
                "enabled": Boolean(False),
                "url": String(),
                "identifier": String(),
            },
            "mattermost": {
                "enabled": Boolean(False),
                "username": String("cuckoo"),
                "url": String(),
                "myurl": String(),
                "show_virustotal": Boolean(True),
                "show_signatures": Boolean(True),
                "show_urls": Boolean(True),
                "hash_filename": Boolean(True),
            },
        },
        "routing": {
            "routing": {
                "route": String("none"),
                "internet": String("none"),
                "rt_table": String("main"),
                "auto_rt": Boolean(True),
                "drop": Boolean(False),
            },
            "inetsim": {
                "enabled": Boolean(False),
                "server": String("192.168.56.1"),
            },
            "tor": {
                "enabled": Boolean(False),
                "dnsport": Int(5353),
                "proxyport": Int(9040),
            },
            "vpn": {
                "enabled": Boolean(False),
                "vpns": List(String, "vpn0"),
            },
            "*": {
                "__section__": "vpn0",
                "name": String("vpn0"),
                "description": String("Spain, Europe"),
                "interface": String("tun0"),
                "rt_table": String("tun0"),
            },
        },
        "vmware": {
            "vmware": {
                "mode": String("gui"),
                "path": Path(
                    "/usr/bin/vmrun",
                    exists=True, writable=False, readable=True
                ),
                "interface": String("virbr0"),
                "machines": List(String, "cuckoo1"),
            },
            "*": {
                "__section__": "cuckoo1",
                "vmx_path": Path(
                    "../cuckoo1/cuckoo1.vmx",
                    exists=True, writable=False, readable=True
                ),
                "snapshot": String("Snapshot1"),
                "platform": String("windows"),
                "ip": String("192.168.54.111"),
                "interface": String(),
                "resultserver_ip": String(),
                "resultserver_port": Int(),
                "tags": String(),
            },
        },
        "vsphere": {
            "vsphere": {
                "host": String("10.0.0.1"),
                "port": Int(443),
                "user": String("username_goes_here"),
                "pwd": String("password_goes_here", sanitize=True),
                "interface": String("eth0"),
                "machines": List(String, "analysis1"),
                "unverified_ssl": Boolean(False),
            },
            "*": {
                "__section__": "analysis1",
                "label": String("cuckoo1"),
                "platform": String("windows"),
                "snapshot": String("snapshot_name"),
                "ip": String("192.168.1.100"),
                "interface": String(),
                "resultserver_ip": String(required=False),
                "resultserver_port": Int(required=False),
                "tags": String(required=False),
            },
        },
        "xenserver": {
            "xenserver": {
                "user": String("root"),
                "password": String("changeme", sanitize=True),
                "url": String("https://xenserver"),
                "interface": String("virbr0"),
                "machines": List(String, "cuckoo1"),
            },
            "*": {
                "__section__": "cuckoo1",
                "uuid": UUID("00000000-0000-0000-0000-000000000000"),
                "snapshot": String(),
                "platform": String("windows"),
                "ip": String("192.168.54.111"),
                "interface": String(),
                "resultserver_ip": String(),
                "resultserver_port": Int(),
                "tags": String(),
            },
        },
    }

    def get_section_types(self, file_name, section, strict=False, loose=False):
        """Get types for a section entry."""
        if section in self.configuration.get(file_name, {}):
            types = self.configuration[file_name][section]
        elif "*" in self.configuration.get(file_name, {}):
            types = self.configuration[file_name]["*"]
            # If multiple default values have been provided, pick one.
            if isinstance(types, (tuple, list)):
                types = types[0]
        elif loose:
            types = {}
        else:
            log.error(
                "Config section %s:%s not found!", file_name, section
            )
            if strict:
                raise CuckooConfigurationError(
                    "Config section %s:%s not found!", file_name, section
                )
            return
        return types

    def __init__(self, file_name="cuckoo", cfg=None, strict=False,
                 loose=False, raw=False):
        """
        @param file_name: file name without extension.
        @param cfg: configuration file path.
        """
        env = {}
        for key, value in os.environ.items():
            if key.startswith("CUCKOO_"):
                env[key] = value

        config = ConfigParser.ConfigParser(env)

        self.env_keys = []
        for key in env.keys():
            self.env_keys.append(key.lower())

        self.sections = {}

        if cfg:
            config.read(cfg)
        else:
            config.read(cwd("conf", "%s.conf" % file_name))

        if file_name not in self.configuration and not loose:
            log.error("Unknown config file %s.conf", file_name)
            return

        for section in config.sections():
            types = self.get_section_types(file_name, section, strict, loose)
            if types is None:
                continue

            self.sections[section] = Dictionary()
            setattr(self, section, self.sections[section])

            try:
                items = config.items(section)
            except ConfigParser.InterpolationMissingOptionError as e:
                log.error("Missing environment variable(s): %s", e)
                raise CuckooConfigurationError(e)

            for name, raw_value in items:
                if name in self.env_keys:
                    continue

                if not raw and name in types:
                    # TODO Is this the area where we should be checking the
                    # configuration values?
                    # if not types[name].check(raw_value):
                    #     print file_name, section, name, raw_value
                    #     raise

                    value = types[name].parse(raw_value)
                else:
                    if not loose:
                        log.error(
                            "Type of config parameter %s:%s:%s not found! "
                            "This may indicate that you've incorrectly filled "
                            "out the Cuckoo configuration, please double "
                            "check it.", file_name, section, name
                        )
                    value = raw_value

                self.sections[section][name] = value

    def get(self, section):
        """Get option.
        @param section: section to fetch.
        @raise CuckooConfigurationError: if section not found.
        @return: option value.
        """
        if section not in self.sections:
            raise CuckooConfigurationError(
                "Option %s is not found in configuration" % section
            )

        return self.sections[section]

    @staticmethod
    def from_confdir(dirpath, loose=False, sanitize=False):
        """Reads all the configuration from a configuration directory. If
        `sanitize` is set, then black out sensitive fields."""
        ret = {}
        for filename in os.listdir(dirpath):
            if not filename.endswith(".conf"):
                continue

            config_name = filename.rsplit(".", 1)[0]
            cfg = Config(
                config_name, cfg=os.path.join(dirpath, filename), loose=loose
            )

            ret[config_name] = {}
            for section, values in cfg.sections.items():
                ret[config_name][section] = {}
                types = cfg.get_section_types(config_name, section) or {}
                for key, value in values.items():
                    if sanitize and key in types and types[key].sanitize:
                        value = "*"*8

                    ret[config_name][section][key] = value
        return ret

def parse_options(options):
    """Parse the analysis options field to a dictionary."""
    ret = {}
    for field in options.split(","):
        if "=" not in field:
            continue

        key, value = field.split("=", 1)
        ret[key.strip()] = value.strip()
    return ret

def emit_options(options):
    """Emit the analysis options from a dictionary to a string."""
    return ",".join("%s=%s" % (k, v) for k, v in options.items())

def config(s, cfg=None, strict=False, raw=False, loose=False, check=False):
    """Fetch a configuration value, denoted as file:section:key."""
    if s.count(":") != 2:
        raise RuntimeError("Invalid configuration entry: %s" % s)

    file_name, section, key = s.split(":")

    if check:
        strict = raw = loose = True

    type_ = Config.configuration.get(file_name, {}).get(section, {}).get(key)
    if strict and type_ is None:
        raise CuckooConfigurationError(
            "No such configuration value exists: %s" % s
        )

    required = type_ is not None and type_.required
    index = file_name, cfg, cwd(), strict, raw, loose

    if index not in _cache:
        _cache[index] = Config(
            file_name, cfg=cfg, strict=strict, raw=raw, loose=loose
        )

    config = _cache[index]

    if strict and required and section not in config.sections:
        raise CuckooConfigurationError(
            "Configuration value %s not present! This may indicate that "
            "you've incorrectly filled out the Cuckoo configuration, "
            "please double check it." % s
        )

    section = config.sections.get(section, {})
    if strict and required and key not in section:
        raise CuckooConfigurationError(
            "Configuration value %s not present! This may indicate that "
            "you've incorrectly filled out the Cuckoo configuration, "
            "please double check it." % s
        )

    value = section.get(key, type_.default if type_ else None)

    if check and not type_.check(value):
        raise CuckooConfigurationError(
            "The configuration value %r found for %s is invalid. Please "
            "update your configuration!" % (value, s)
        )

    return value

def cast(s, value):
    """Cast a configuration value as per its type."""
    if s.count(":") != 2:
        raise RuntimeError("Invalid configuration entry: %s" % s)

    file_name, section, key = s.split(":")

    type_ = Config.configuration.get(file_name, {}).get(section, {}).get(key)
    if type_ is None:
        raise CuckooConfigurationError(
            "No such configuration value exists: %s" % s
        )

    return type_.parse(value)
