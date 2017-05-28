# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cuckoo.common.config import cast

def _041_042(c):
    c["cuckoo"]["cuckoo"]["analysis_size_limit"] = 104857600
    c["virtualbox"]["virtualbox"]["timeout"] = 300
    c["vmware"] = {
        "vmware": {
            "mode": "gui",
            "path": "/usr/bin/vmrun",
            "machines": ["cuckoo1"],
        },
        "cuckoo1": {
            "label": "../vmware-xp3.vmx,Snapshot1",
            "platform": "windows",
            "ip": "192.168.54.111",
        },
    }
    return c

def _042_050(c):
    analysis_timeout = c["cuckoo"]["cuckoo"].pop("analysis_timeout", None)
    critical_timeout = c["cuckoo"]["cuckoo"].pop("critical_timeout", None)
    c["cuckoo"]["cuckoo"]["version_check"] = True
    c["cuckoo"]["cuckoo"]["memory_dump"] = False
    c["cuckoo"]["processing"] = {
        "analysis_size_limit": c["cuckoo"]["cuckoo"].pop(
            "analysis_size_limit", None
        ),
        "resolve_dns": True,
    }
    c["cuckoo"]["database"] = {
        "connection": None,
        "timeout": None,
    }
    timeout = c["virtualbox"]["virtualbox"].pop("timeout", None)
    c["cuckoo"]["timeouts"] = {
        "default": cast("cuckoo:timeouts:default", analysis_timeout),
        "critical": cast("cuckoo:timeouts:critical", critical_timeout),
        "vm_state": cast("cuckoo:timeouts:vm_state", timeout),
    }
    sniffer = c["cuckoo"]["cuckoo"].pop("use_sniffer", None)
    c["cuckoo"]["sniffer"] = {
        "enabled": sniffer,
        "tcpdump": "/usr/sbin/tcpdump",
        "interface": "vboxnet0",
        "bpf": None,
    }
    c["cuckoo"]["graylog"] = {
        "enabled": False,
        "host": "localhost",
        "port": 12201,
        "level": "error",
    }
    return c

def _050_060(c):
    c["cuckoo"]["resultserver"] = {
        "ip": "192.168.56.1",
        "port": 2042,
        "store_csvs": False,
        "upload_max_size": 10485760,
    }
    c["processing"] = {
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
    return c

def _060_100(c):
    c["auxiliary"] = {
        "sniffer": {
            "enabled": cast(
                "auxiliary:sniffer:enabled",
                c["cuckoo"]["sniffer"]["enabled"]
            ),
            "tcpdump": c["cuckoo"]["sniffer"]["tcpdump"],
            "interface": c["cuckoo"]["sniffer"]["interface"],
            "bpf": c["cuckoo"]["sniffer"].get("bpf"),
        },
    }
    c["cuckoo"].pop("sniffer", None)
    c["cuckoo"]["cuckoo"]["delete_bin_copy"] = False
    machinery = c["cuckoo"]["cuckoo"].pop("machine_manager", None)
    c["cuckoo"]["cuckoo"]["machinery"] = machinery
    c["cuckoo"]["cuckoo"]["reschedule"] = False
    c["cuckoo"]["cuckoo"]["process_results"] = True
    c["cuckoo"]["cuckoo"]["max_analysis_count"] = 0
    c["cuckoo"]["cuckoo"]["freespace"] = 64
    c["cuckoo"].pop("graylog", None)
    c["esx"] = {
        "esx": {
            "dsn": "esx://127.0.0.1/?no_verify=1",
            "username": "username_goes_here",
            "password": "password_goes_here",
            "machines": ["analysis1"],
        },
        "analysis1": {
            "label": "cuckoo1",
            "platform": "windows",
            "snapshot": "clean_snapshot",
            "ip": "192.168.122.105",
        }
    }
    c["memory"] = {
        "basic": {
            "guest_profile": "WinXPSP2x86",
            "delete_memdump": False,
        },
        "malfind": {
            "enabled": True,
            "filter": True,
        },
        "apihooks": {
            "enabled": False,
            "filter": True,
        },
        "pslist": {
            "enabled": True,
            "filter": False,
        },
        "psxview": {
            "enabled": True,
            "filter": False,
        },
        "callbacks": {
            "enabled": True,
            "filter": False,
        },
        "idt": {
            "enabled": True,
            "filter": False,
        },
        "timers": {
            "enabled": True,
            "filter": False,
        },
        "messagehooks": {
            "enabled": False,
            "filter": False,
        },
        "getsids": {
            "enabled": True,
            "filter": False,
        },
        "privs": {
            "enabled": True,
            "filter": False,
        },
        "dlllist": {
            "enabled": True,
            "filter": True,
        },
        "handles": {
            "enabled": True,
            "filter": True,
        },
        "ldrmodules": {
            "enabled": True,
            "filter": True,
        },
        "mutantscan": {
            "enabled": True,
            "filter": True,
        },
        "devicetree": {
            "enabled": True,
            "filter": True,
        },
        "svcscan": {
            "enabled": True,
            "filter": True,
        },
        "modscan": {
            "enabled": True,
            "filter": True,
        },
        "mask": {
            "enabled": False,
            "pid_generic": None,
        },
    }
    c["processing"]["memory"] = {
        "enabled": False,
    }
    c["reporting"].pop("pickled", None)
    c["reporting"]["mmdef"] = {
        "enabled": False,
    }
    c["reporting"].pop("metadata", None)
    c["reporting"].pop("maec11", None)
    c["reporting"]["maec41"] = {
        "enabled": False,
        "mode": "overview",
        "processtree": True,
        "output_handles": False,
        "static": True,
        "strings": True,
        "virustotal": True,
    }
    c["reporting"]["mongodb"]["host"] = "127.0.0.1"
    c["reporting"]["mongodb"]["port"] = 27017

    for machine in c["vmware"]["vmware"]["machines"]:
        label, snapshot = c["vmware"][machine]["label"].split(",", 1)
        c["vmware"][machine]["label"] = label
        c["vmware"][machine]["snapshot"] = snapshot
    return c

def _100_110(c):
    c["cuckoo"]["cuckoo"]["tmppath"] = "/tmp"
    return c

def _111_120(c):
    c["cuckoo"]["cuckoo"]["terminate_processes"] = False
    c["cuckoo"]["cuckoo"]["max_machines_count"] = 0
    c["cuckoo"]["processing"]["sort_pcap"] = True
    c["memory"]["yarascan"] = {
        "enabled": True,
        "filter": True,
    }
    c["memory"]["ssdt"] = {
        "enabled": True,
        "filter": True,
    }
    c["memory"]["gdt"] = {
        "enabled": True,
        "filter": True,
    }
    c["physical"] = {
        "physical": {
            "machines": ["physical1"],
            "user": "username",
            "password": "password",
        },
        "physical1": {
            "label": "physical1",
            "platform": "windows",
            "ip": "192.168.56.101",
        }
    }
    c["processing"]["procmemory"] = {
        "enabled": True,
    }
    c["processing"]["virustotal"]["timeout"] = 60
    c["reporting"]["jsondump"]["indent"] = 4
    c["reporting"]["jsondump"]["encoding"] = "latin-1"
    c["reporting"]["mongodb"]["db"] = "cuckoo"
    c["reporting"]["mongodb"]["store_memdump"] = True
    c["reporting"].pop("hpfclient", None)

    for machine in c["vmware"]["vmware"]["machines"]:
        c["vmware"][machine]["vmx_path"] = (
            c["vmware"][machine].pop("label", None)
        )

    c["xenserver"] = {
        "xenserver": {
            "user": "root",
            "password": "changeme",
            "url": "https://xenserver",
            "machines": ["cuckoo1"],
        },
        "cuckoo1": {
            "uuid": "00000000-0000-0000-0000-000000000000",
            "platform": "windows",
            "ip": "192.168.54.111",
        }
    }
    return c

def _120_20c1(c):
    interface = c["auxiliary"]["sniffer"].pop("interface", "vboxnet0")
    c["auxiliary"]["mitm"] = {
        "enabled": False,
        "mitmdump": "/usr/local/bin/mitmdump",
        "port_base": 50000,
        "script": "data/mitm.py",
        "certificate": "bin/cert.p12",
    }
    c["auxiliary"]["services"] = {
        "enabled": False,
        "services": "honeyd",
        "timeout": 0,
    }
    c["avd"] = {
        "avd": {
            "mode": "headless",
            "emulator_path": "/home/cuckoo/android-sdk-linux/tools/emulator",
            "adb_path": "/home/cuckoo/android-sdk-linux/platform-tools/adb",
            "avd_path": "/home/cuckoo/.android/avd",
            "reference_machine": "cuckoo-bird",
            "machines": ["cuckoo1"],
        },
        "cuckoo1": {
            "label": "cuckoo1",
            "platform": "android",
            "ip": "127.0.0.1",
            "emulator_port": 5554,
            "resultserver_ip": "10.0.2.2",
            "resultserver_port": 2042,
        },
    }
    c["cuckoo"]["cuckoo"]["max_vmstartup_count"] = 10
    c["cuckoo"]["cuckoo"]["rooter"] = "/tmp/cuckoo-rooter"
    c["cuckoo"]["routing"] = {
        "route": "none",
        "internet": "none",
    }
    c["cuckoo"]["resultserver"].pop("store_csvs", None)
    if c["cuckoo"]["timeouts"]["vm_state"] == 300:
        c["cuckoo"]["timeouts"]["vm_state"] = 60
    c["esx"]["esx"]["interface"] = "eth0"
    c["kvm"]["kvm"]["interface"] = "virbr0"
    c["memory"]["sockscan"] = {
        "enabled": True,
        "filter": False,
    }
    c["memory"]["netscan"] = {
        "enabled": True,
        "filter": False,
    }
    c["physical"]["physical"]["interface"] = "eth0"
    c["physical"]["fog"] = {
        "hostname": "none",
        "username": "fog",
        "password": "password",
    }
    c["processing"]["apkinfo"] = {
        "enabled": False,
        "decompilation_threshold": 5000000,
    }
    c["processing"]["baseline"] = {
        "enabled": False,
    }
    c["processing"]["buffer"] = {
        "enabled": True,
    }
    c["processing"]["droidmon"] = {
        "enabled": False,
    }
    c["processing"]["dumptls"] = {
        "enabled": True,
    }
    c["processing"]["googleplay"] = {
        "enabled": False,
        "android_id": None,
        "google_login": None,
        "google_password": None,
    }
    c["processing"]["procmemory"]["idapro"] = False
    c["processing"]["screenshots"] = {
        "enabled": False,
        "tesseract": "/usr/bin/tesseract",
    }
    c["processing"]["snort"] = {
        "enabled": False,
        "snort": "/usr/local/bin/snort",
        "conf": "/etc/snort/snort.conf",
    }
    c["processing"]["suricata"] = {
        "enabled": False,
        "suricata": "/usr/bin/suricata",
        "conf": "/etc/suricata/suricata.yaml",
        "eve_log": "eve.json",
        "files_log": "files-json.log",
        "files_dir": "files",
        "socket": None,
    }
    c["processing"]["virustotal"]["scan"] = False
    c["qemu"] = {
        "qemu": {
            "path": "/usr/bin/qemu-system-x86_64",
            "machines": ["vm1", "vm2"],
            "interface": "qemubr",
        },
        "vm1": {
            "label": "vm1",
            "image": "/home/rep/vms/qvm_wheezy64_1.qcow2",
            "platform": "linux",
            "ip": "192.168.55.2",
            "interface": "qemubr",
            "resultserver_ip": "192.168.55.1",
            "tags": "debian_wheezy,64_bit",
        },
        "vm2": {
            "label": "vm2",
            "image": "/home/rep/vms/qvm_wheezy64_1.qcow2",
            "arch": "mipsel",
            "kernel_path": "{imagepath}/vmlinux-3.16.0-4-4kc-malta-mipsel",
            "platform": "linux",
            "ip": "192.168.55.3",
            "interface": "qemubr",
            "tags": "debian_wheezy,mipsel",
        },
    }
    c["reporting"]["jsondump"]["calls"] = True
    c["reporting"].pop("mmdef", None)
    c["reporting"].pop("maec41", None)
    c["reporting"]["reporthtml"]["enabled"] = False
    c["reporting"]["mongodb"]["paginate"] = 100
    c["reporting"]["moloch"] = {
        "enabled": False,
        "host": None,
        "moloch_capture": "/data/moloch/bin/moloch-capture",
        "conf": "/data/moloch/etc/config.ini",
        "instance": "cuckoo",
    }
    c["virtualbox"]["virtualbox"]["mode"] = "headless"
    c["virtualbox"]["virtualbox"]["interface"] = interface
    c["virtualbox"]["honeyd"] = {
        "label": "honeyd",
        "platform": "linux",
        "ip": "192.168.56.102",
        "tags": "service, honeyd",
        "options": "nictrace noagent",
    }
    c["vmware"]["vmware"]["interface"] = "virbr0"
    c["vpn"] = {
        "vpn": {
            "enabled": False,
            "vpns": "vpn0",
        },
        "vpn0": {
            "name": "vpn0",
            "description": "Spain, Europe",
            "interface": "tun0",
        },
    }
    c["vsphere"] = {
        "vsphere": {
            "host": "10.0.0.1",
            "port": 443,
            "user": "username_goes_here",
            "pwd": "password_goes_here",
            "machines": ["analysis1"],
            "interface": "eth0",
        },
        "analysis1": {
            "label": "cuckoo1",
            "platform": "windows",
            "snapshot": "cuckoo_ready_running",
            "ip": "192.168.1.1",
        },
    }
    c["xenserver"]["xenserver"]["interface"] = "virbr0"
    return c

def _20c1_20c2(c):
    c["auxiliary"]["reboot"] = {
        "enabled": True,
    }
    c["cuckoo"]["routing"]["rt_table"] = "main"
    c["cuckoo"]["routing"]["auto_rt"] = True
    c["cuckoo"]["resultserver"]["force_port"] = False
    if c["cuckoo"]["timeouts"]["critical"] == 600:
        c["cuckoo"]["timeouts"]["critical"] = 60
    c["processing"]["misp"] = {
        "enabled": False,
        "url": None,
        "apikey": None,
        "maxioc": 100,
    }
    c["processing"]["network"]["whitelist-dns"] = False
    c["processing"]["network"]["allowed-dns"] = None
    c["processing"]["procmemory"]["extract_img"] = True
    c["processing"]["procmemory"]["dump_delete"] = False
    c["processing"]["procmon"] = {
        "enabled": True,
    }
    c["processing"]["static"]["pdf_timeout"] = 60
    c["processing"]["irma"] = {
        "enabled": False,
        "timeout": 60,
        "scan": False,
        "force": False,
        "url": None,
    }
    c["reporting"]["elasticsearch"] = {
        "enabled": False,
        "hosts": "127.0.0.1",
        "calls": False,
        "index": "cuckoo",
        "index_time_pattern": "yearly",
        "cuckoo_node": None,
    }
    c["reporting"]["notification"] = {
        "enabled": False,
        "url": None,
        "identifier": None,
    }
    c["reporting"]["mattermost"] = {
        "enabled": False,
        "username": "cuckoo",
        "url": None,
        "myurl": None,
        "show-virustotal": False,
        "show-signatures": False,
        "show-urls": False,
        "hash-filename": False,
    }

    c["vpn"]["vpn"].pop("auto_rt", None)
    for vpn in c["vpn"]["vpn"]["vpns"].split(","):
        if not vpn.strip():
            continue

        c["vpn"][vpn.strip()]["rt_table"] = c["vpn"][vpn.strip()]["interface"]

    return c

def _20c2_200(c):
    if c["auxiliary"]["mitm"]["script"] == "data/mitm.py":
        c["auxiliary"]["mitm"]["script"] = "mitm.py"
    if c["cuckoo"]["cuckoo"]["freespace"] == 64:
        c["cuckoo"]["cuckoo"]["freespace"] = 1024
    if c["cuckoo"]["cuckoo"]["tmppath"] == "/tmp":
        c["cuckoo"]["cuckoo"]["tmppath"] = None
    if c["cuckoo"]["processing"]["analysis_size_limit"] == 100*1024*1024:
        c["cuckoo"]["processing"]["analysis_size_limit"] = 128*1024*1024
    if c["cuckoo"]["resultserver"]["upload_max_size"] == 10*1024*1024:
        c["cuckoo"]["resultserver"]["upload_max_size"] = 128*1024*1024
    c["cuckoo"]["feedback"] = {
        "enabled": False,
        "name": None,
        "company": None,
        "email": None,
    }
    c["processing"]["network"]["whitelist_dns"] = cast(
        "processing:network:whitelist_dns",
        c["processing"]["network"].pop("whitelist-dns", None)
    )
    c["processing"]["network"]["allowed_dns"] = cast(
        "processing:network:allowed_dns",
        c["processing"]["network"].pop("allowed-dns", None)
    )
    c["processing"]["procmemory"]["extract_dll"] = False
    # If default key, disable VirusTotal by default.
    if c["processing"]["virustotal"]["key"] == "a0283a2c3d55728300d064874239b5346fb991317e8449fe43c902879d758088":
        c["processing"]["virustotal"]["enabled"] = False
    for vm in c["qemu"]:
        if "kernel_path" in c["qemu"][vm]:
            c["qemu"][vm]["kernel"] = c["qemu"][vm].pop("kernel_path")
    if c["qemu"]["qemu"]["machines"] == ["vm1", "vm2"]:
        c["qemu"]["qemu"]["machines"].append("vm3")
        c["qemu"]["vm3"] = {
            "label": "vm3",
            "image": "/home/rep/vms/qvm_wheezy64_1.qcow2",
            "arch": "arm",
            "platform": "linux",
            "ip": "192.168.55.4",
            "interface": "qemubr",
            "tags": "debian_wheezy,arm",
            "kernel": "{imagepath}/vmlinuz-3.2.0-4-versatile-arm",
            "initrd": "{imagepath}/initrd-3.2.0-4-versatile-arm",
        }
    c["reporting"]["elasticsearch"]["hosts"] = cast(
        "reporting:elasticsearch:hosts",
        c["reporting"]["elasticsearch"]["hosts"]
    )
    c["reporting"]["elasticsearch"]["timeout"] = 300
    c["reporting"]["feedback"] = {
        "enabled": False,
    }
    c["reporting"]["jsondump"].pop("encoding")
    c["reporting"]["misp"] = {
        "enabled": False,
        "url": None,
        "apikey": None,
        "mode": "maldoc ipaddr hashes url",
    }
    c["reporting"]["mattermost"]["hash_url"] = False
    old_items = (
        "show-virustotal", "show-signatures", "show-urls", "hash-filename",
    )
    for old_item in old_items:
        new_item = old_item.replace("-", "_")
        c["reporting"]["mattermost"][new_item] = cast(
            "reporting:mattermost:%s" % new_item,
            c["reporting"]["mattermost"].pop(old_item, False)
        )

    c["reporting"]["moloch"]["insecure"] = False
    c["reporting"]["mongodb"]["username"] = None
    c["reporting"]["mongodb"]["password"] = None

    if "url" not in c["reporting"]["notification"]:
        c["reporting"]["notification"]["url"] = None

    c["reporting"]["singlefile"] = {
        "enabled": cast(
            "reporting:singlefile:enabled",
            c["reporting"]["reporthtml"]["enabled"]
        ),
        "html": cast(
            "reporting:singlefile:html",
            c["reporting"]["reporthtml"]["enabled"]
        ),
        "pdf": False,
    }
    c["reporting"].pop("reporthtml")

    c["routing"] = {
        "routing": {
            "drop": False,
        },
        "inetsim": {
            "enabled": False,
            "server": "192.168.56.1",
        },
        "tor": {
            "enabled": False,
            "dnsport": 5353,
            "proxyport": 9040,
        },
        "vpn": {
            "enabled": cast(
                "routing:vpn:enabled", c["vpn"]["vpn"].pop("enabled", None)
            ),
            "vpns": [],
        },
    }

    for item in ("route", "internet", "rt_table", "auto_rt"):
        c["routing"]["routing"][item] = cast(
            "routing:routing:%s" % item, c["cuckoo"]["routing"].pop(item, None)
        )

    for vpn in c["vpn"]["vpn"]["vpns"].split(","):
        if not vpn.strip():
            continue

        c["routing"]["vpn"]["vpns"].append(vpn.strip())
        c["routing"][vpn.strip()] = c["vpn"].pop(vpn.strip(), None)

    c.pop("vpn", None)
    c["vsphere"]["vsphere"]["unverified_ssl"] = False
    return c

def _200_201(c):
    c["memory"]["mask"]["pid_generic"] = cast(
        "memory:mask:pid_generic", c["memory"]["mask"]["pid_generic"]
    )
    return c

def _201_202(c):
    machineries = (
        "virtualbox", "avd", "esx", "kvm", "physical", "qemu", "vmware",
        "vsphere", "xenserver",
    )
    for machinery in machineries:
        for machine in c[machinery][machinery]["machines"]:
            c[machinery][machine]["osprofile"] = None
    return c

def _203_204(c):
    c["processing"]["extracted"] = {
        "enabled": True,
    }
    return c

migrations = {
    "0.4.0": ("0.4.1", None),
    "0.4.1": ("0.4.2", _041_042),
    "0.4.2": ("0.5.0", _042_050),
    "0.5.0": ("0.6.0", _050_060),
    "0.6.0": ("1.0.0", _060_100),
    "1.0.0": ("1.1.0", _100_110),
    "1.1.0": ("1.1.1", None),
    "1.1.1": ("1.2.0", _111_120),
    "1.2.0": ("2.0-rc1", _120_20c1),
    "2.0-rc1": ("2.0-rc2", _20c1_20c2),
    "2.0-rc2": ("2.0.0", _20c2_200),
    "2.0.0": ("2.0.1", _200_201),
    "2.0.1": ("2.0.2", _201_202),
    "2.0.2": ("2.0.3", None),
    "2.0.3": ("2.0.4", _203_204),

    # We're also capable of migrating away from 2.0-dev which basically means
    # that we might have to a partial migration from either 2.0-rc2 or 2.0-rc1.
    # TODO Most likely we'll have to work out some tweaks in the migrations.
    # TODO Provide the option to push out feedback to the Core Developers if
    # an exception occurs during the configuration migration phase.
    "2.0-dev": ("1.2.0", None),
}

# Mapping from actual version numbers to "full" / beautified version numbers.
mapping = {
    "0.4": "0.4.0", "0.5": "0.5.0", "0.6": "0.6.0", "1.0": "1.0.0",
    "1.1": "1.1.0", "1.2": "1.2.0",
}

def migrate(c, current, to=None):
    """Upgrade the configuration 'c' from 'current' to 'to'."""
    while current != to and mapping.get(current, current) in migrations:
        current, migration = migrations[mapping.get(current, current)]
        c = migration(c) if migration else c
    return c
