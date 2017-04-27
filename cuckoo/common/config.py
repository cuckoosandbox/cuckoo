# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ConfigParser
import click
import os
import logging
import re

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

    def __init__(self, subclass, default, sep=",", strip=True):
        self.subclass = subclass
        self.sep = sep
        self.strip = strip
        super(List, self).__init__(default)

    def parse(self, value):
        if value is None:
            return []

        try:
            ret = []

            if isinstance(value, (tuple, list)):
                for entry in value:
                    ret.append(self.subclass().parse(entry))
                return ret

            for entry in re.split("[%s]" % self.sep, value):
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
        return (", " if self.sep[0] == "," else self.sep[0]).join(value or "")

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
                "freespace": Int(1024),
                "tmppath": Path(
                    exists=True, writable=True, readable=False,
                    allow_empty=True
                ),
                "rooter": Path(
                    "/tmp/cuckoo-rooter",
                    exists=False, writable=False, readable=False
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
                "upload_max_size": Int(128 * 1024 * 1024),
            },
            "processing": {
                "analysis_size_limit": Int(128 * 1024 * 1024),
                "resolve_dns": Boolean(True),
                "sort_pcap": Boolean(True),
            },
            "database": {
                "connection": String(sanitize=True),
                "timeout": Int(60, allow_empty=True),
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
                    exists=False, writable=False, readable=True
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
                "options": List(String, None, ",\\s"),
                "osprofile": String(required=False),
            },
            "__star__": ("virtualbox", "machines"),
        },
        "auxiliary": {
            "sniffer": {
                "enabled": Boolean(True),
                "tcpdump": Path(
                    "/usr/sbin/tcpdump",
                    exists=False, writable=False, readable=True
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
                "osprofile": String(required=False),
            },
            "__star__": ("avd", "machines"),
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
                "ip": String("192.168.122.101"),
                "snapshot": String("clean_snapshot"),
                "interface": String(),
                "resultserver_ip": String(),
                "resultserver_port": Int(),
                "tags": String(),
                "osprofile": String(required=False),
            },
            "__star__": ("esx", "machines"),
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
                "ip": String("192.168.122.101"),
                "snapshot": String(),
                "interface": String(),
                "resultserver_ip": String(),
                "resultserver_port": Int(),
                "tags": String(),
                "osprofile": String(required=False),
            },
            "__star__": ("kvm", "machines"),
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
                "pid_generic": List(String, None),
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
                "osprofile": String(required=False),
            },
            "__star__": ("physical", "machines"),
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
            "extracted": {
                "enabled": Boolean(True, required=False),
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
                "extract_dll": Boolean(False),
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
                "enabled": Boolean(False),
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
                "machines": List(String, "vm1,vm2,vm3"),
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
                    "kernel": String(),
                    "initrd": String(),
                    "osprofile": String(required=False),
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
                    "kernel": String(
                        "{imagepath}/vmlinux-3.16.0-4-4kc-malta-mipsel"
                    ),
                    "osprofile": String(""),
                }, {
                    "__section__": "vm3",
                    "label": String("vm3"),
                    "image": Path(
                        "/home/rep/vms/qvm_wheezy64_1.qcow2",
                        exists=True, writable=False, readable=True
                    ),
                    "arch": String("arm"),
                    "platform": String("linux"),
                    "ip": String("192.168.55.4"),
                    "interface": String("qemubr"),
                    "tags": String("debian_wheezy,arm"),
                    "kernel": String(
                        "{imagepath}/vmlinuz-3.2.0-4-versatile-arm"
                    ),
                    "initrd": String(
                        "{imagepath}/initrd-3.2.0-4-versatile-arm"
                    ),
                    "osprofile": String(""),
                },
            ],
            "__star__": ("qemu", "machines"),
        },
        "reporting": {
            "feedback": {
                "enabled": Boolean(False),
            },
            "jsondump": {
                "enabled": Boolean(True),
                "indent": Int(4),
                "calls": Boolean(True),
            },
            "singlefile": {
                "enabled": Boolean(False),
                "html": Boolean(False),
                "pdf": Boolean(False),
            },
            "misp": {
                "enabled": Boolean(False),
                "url": String(),
                "apikey": String(sanitize=True),
                "mode": String("maldoc ipaddr hashes url"),
            },
            "mongodb": {
                "enabled": Boolean(False),
                "host": String("127.0.0.1"),
                "port": Int(27017),
                "db": String("cuckoo"),
                "store_memdump": Boolean(True),
                "paginate": Int(100),
                "username": String(),
                "password": String(),
            },
            "elasticsearch": {
                "enabled": Boolean(False),
                "hosts": List(String, "127.0.0.1"),
                "timeout": Int(300),
                "calls": Boolean(False),
                "index": String("cuckoo"),
                "index_time_pattern": String("yearly"),
                "cuckoo_node": String(),
            },
            "moloch": {
                "enabled": Boolean(False),
                "host": String(),
                "insecure": Boolean(False),
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
                "show_virustotal": Boolean(False),
                "show_signatures": Boolean(False),
                "show_urls": Boolean(False),
                "hash_filename": Boolean(False),
                "hash_url": Boolean(False),
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
            "__star__": ("vpn", "vpns"),
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
                "osprofile": String(required=False),
            },
            "__star__": ("vmware", "machines"),
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
                "ip": String("192.168.122.101"),
                "interface": String(),
                "resultserver_ip": String(required=False),
                "resultserver_port": Int(required=False),
                "tags": String(required=False),
                "osprofile": String(required=False),
            },
            "__star__": ("vsphere", "machines"),
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
                "osprofile": String(required=False),
            },
            "__star__": ("xenserver", "machines"),
        },
    }

    def get_section_types(self, file_name, section, strict=False, loose=False):
        """Get types for a section entry."""
        section_types = get_section_types(file_name, section)
        if not section_types and not loose:
            log.error(
                "Config section %s:%s not found!", file_name, section
            )
            if strict:
                raise CuckooConfigurationError(
                    "Config section %s:%s not found!", file_name, section
                )
            return
        return section_types

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

        env["CUCKOO_CWD"] = cwd()
        env["CUCKOO_APP"] = os.environ.get("CUCKOO_APP", "")
        config = ConfigParser.ConfigParser(env)

        self.env_keys = []
        for key in env.keys():
            self.env_keys.append(key.lower())

        self.sections = {}

        try:
            config.read(cfg or cwd("conf", "%s.conf" % file_name))
        except ConfigParser.ParsingError as e:
            raise CuckooConfigurationError(
                "There was an error reading in the $CWD/conf/%s.conf "
                "configuration file. Most likely there are leading "
                "whitespaces in front of one of the key=value lines defined. "
                "More information from the original exception: %s" %
                (file_name, e)
            )

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
                raise CuckooConfigurationError(
                    "Missing environment variable: %s" % e
                )

            for name, raw_value in items:
                if name in self.env_keys:
                    continue

                if "\n" in raw_value:
                    wrong_key = "???"
                    try:
                        wrong_key = raw_value.split("\n", 1)[1].split()[0]
                    except:
                        pass

                    raise CuckooConfigurationError(
                        "There was an error reading in the $CWD/conf/%s.conf "
                        "configuration file. Namely, there are one or more "
                        "leading whitespaces before the definition of the "
                        "'%s' key/value pair in the '%s' section. Please "
                        "remove those leading whitespaces as Python's default "
                        "configuration parser is unable to handle those "
                        "properly." % (file_name, wrong_key, section)
                    )

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
                types = cfg.get_section_types(
                    config_name, section, loose=loose
                ) or {}
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
    return ",".join("%s=%s" % (k, v) for k, v in sorted(options.items()))

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

def get_section_types(file_name, section, strict=False):
    if section in Config.configuration.get(file_name, {}):
        return Config.configuration[file_name][section]

    if "__star__" not in Config.configuration.get(file_name, {}):
        return {}

    if strict:
        section_, key = Config.configuration[file_name]["__star__"]
        if section not in config("%s:%s:%s" % (file_name, section_, key)):
            return {}

    if "*" in Config.configuration.get(file_name, {}):
        section_types = Config.configuration[file_name]["*"]
        # If multiple default values have been provided, pick one.
        if isinstance(section_types, (tuple, list)):
            section_types = section_types[0]
        return section_types
    return {}

def config2(file_name, section):
    keys = get_section_types(file_name, section, strict=True)
    if not keys:
        raise CuckooConfigurationError(
            "No such configuration section exists: %s:%s" %
            (file_name, section)
        )

    ret = Dictionary()
    for key in keys:
        if key == "__star__" or key == "*":
            continue
        ret[key] = config("%s:%s:%s" % (file_name, section, key))
    return ret

def cast(s, value):
    """Cast a configuration value as per its type."""
    if s.count(":") != 2:
        raise RuntimeError("Invalid configuration entry: %s" % s)

    file_name, section, key = s.split(":")
    type_ = get_section_types(file_name, section).get(key)
    if type_ is None:
        raise CuckooConfigurationError(
            "No such configuration value exists: %s" % s
        )

    return type_.parse(value)

def read_kv_conf(filepath):
    """Reads a flat Cuckoo key/value configuration file."""
    ret = {}
    for line in open(filepath, "rb"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if "=" not in line:
            raise CuckooConfigurationError(
                "Invalid flat configuration line: %s (missing '=' character)" %
                line
            )

        key, raw_value = line.split("=", 1)
        key, raw_value = key.replace(".", ":").strip(), raw_value.strip()
        try:
            value = cast(key, raw_value)
        except (CuckooConfigurationError, RuntimeError) as e:
            raise CuckooConfigurationError(
                "Invalid flat configuration line: %s (error %s)" % (line, e)
            )

        if raw_value and value is None:
            raise CuckooConfigurationError(
                "Invalid flat configuration entry: %s is None" % key
            )

        a, b, c = key.split(":")
        ret[a] = ret.get(a, {})
        ret[a][b] = ret[a].get(b, {})
        ret[a][b][c] = value
    return ret
