# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

def _040_041(c):
    return c

def _041_042(c):
    c["cuckoo"]["cuckoo"]["analysis_size_limit"] = 104857600
    c["virtualbox"]["virtualbox"]["timeout"] = 300
    c["vmware"] = {
        "vmware": {
            "mode": "gui",
            "path": "/usr/bin/vmrun",
            "machines": "cuckoo1",
        },
        "cuckoo1": {
            "label": "../vmware-xp3.vmx,Snapshot1",
            "platform": "windows",
            "ip": "192.168.54.111",
        },
    }
    return c

def _042_050(c):
    analysis_timeout = c["cuckoo"]["cuckoo"].pop("analysis_timeout")
    critical_timeout = c["cuckoo"]["cuckoo"].pop("critical_timeout")
    c["cuckoo"]["cuckoo"]["version_check"] = True
    c["cuckoo"]["cuckoo"]["memory_dump"] = False
    analysis_size_limit = c["cuckoo"]["cuckoo"].pop("analysis_size_limit")
    c["cuckoo"]["processing"] = {
        "analysis_size_limit": analysis_size_limit,
        "resolve_dns": True,
    }
    c["cuckoo"]["database"] = {
        "connection": None,
        "timeout": None,
    }
    timeout = c["virtualbox"]["virtualbox"].pop("timeout")
    c["cuckoo"]["timeouts"] = {
        "default": analysis_timeout,
        "critical": critical_timeout,
        "vm_state": timeout,
    }
    sniffer = c["cuckoo"]["cuckoo"].pop("use_sniffer")
    c["cuckoo"]["sniffer"] = {
        "enabled": sniffer,
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
        "sniffer": c["cuckoo"].pop("sniffer"),
    }
    c["cuckoo"]["cuckoo"]["delete_bin_copy"] = False
    machinery = c["cuckoo"]["cuckoo"].pop("machine_manager")
    c["cuckoo"]["cuckoo"]["machinery"] = machinery
    c["cuckoo"]["cuckoo"]["reschedule"] = False
    c["cuckoo"]["cuckoo"]["process_results"] = True
    c["cuckoo"]["cuckoo"]["max_analysis_count"] = 0
    c["cuckoo"]["cuckoo"]["freespace"] = 64
    c["cuckoo"].pop("graylog")
    c["esx"] = {
        "esx": {
            "dsn": "esx://127.0.0.1/?no_verify=1",
            "username": "username_goes_here",
            "password": "password_goes_here",
            "machines": "analysis1",
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
    c["reporting"].pop("pickled")
    c["reporting"]["mmdef"] = {
        "enabled": False,
    }
    c["reporting"].pop("metadata")
    c["reporting"].pop("maec11")
    c["reporting"]["maec40"] = {
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

    for machine in c["vmware"]["vmware"]["machines"].split(","):
        if not machine.strip():
            continue

        label, snapshot = c["vmware"][machine]["label"].split(",", 1)
        c["vmware"][machine]["label"] = label
        c["vmware"][machine]["snapshot"] = snapshot
    return c

def _100_110(c):
    c["cuckoo"]["cuckoo"]["tmppath"] = "/tmp"
    return c

def _110_120(c):
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
            "machines": "physical1",
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
    c["reporting"].pop("hpfclient")

    for machine in c["vmware"]["vmware"]["machines"].split(","):
        if not machine.strip():
            continue

        c["vmware"][machine]["vmx_path"] = c["vmware"][machine].pop("label")

    c["xenserver"] = {
        "xenserver": {
            "user": "root",
            "password": "changeme",
            "url": "https://xenserver",
            "machines": "cuckoo1",
        },
        "cuckoo1": {
            "uuid": "00000000-0000-0000-0000-000000000000",
            "platform": "windows",
            "ip": "192.168.54.111",
        }
    }
    return c

def _120_20c1(c):
    interface = c["auxiliary"]["sniffer"].pop("interface")
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
            "machines": "cuckoo1",
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
    c["cuckoo"]["resultserver"].pop("store_csvs")
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
    }
    c["processing"]["suricata"] = {
        "enabled": False,
    }
    c["processing"]["virustotal"]["scan"] = 0
    c["qemu"] = {
        "qemu": {
            "path": "/usr/bin/qemu-system-x86_64",
            "machines": "vm1,vm2",
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
    c["reporting"].pop("mmdef")
    c["reporting"].pop("maec40")
    c["reporting"]["reporthtml"]["enabled"] = False
    c["reporting"]["mongodb"]["paginate"] = 100
    c["reporting"]["moloch"] = {
        "enabled": False,
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
            "machines": "analysis1",
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
    }
    c["reporting"]["elasticsearch"] = {
        "enabled": False,
        "hosts": "127.0.0.1",
        "calls": False,
    }
    c["reporting"]["notification"] = {
        "enabled": False,
        "url": None,
        "identifier": None,
    }
    c["reporting"]["mattermost"] = {
        "enabled": False,
        "username": "cuckoo",
    }

    for vpn in c["vpn"]["vpn"]["vpns"].split(","):
        if not vpn.strip():
            continue

        c["vpn"][vpn]["rt_table"] = c["vpn"][vpn]["interface"]

    return c

def _20c2_200(c):
    if c["auxiliary"]["mitm"]["script"] == "data/mitm.py":
        c["auxiliary"]["mitm"]["script"] = "mitm.py"
    if c["cuckoo"]["cuckoo"]["tmppath"] == "/tmp":
        c["cuckoo"]["cuckoo"]["tmppath"] = None
    c["processing"]["network"]["whitelist_dns"] = (
        c["processing"]["network"].pop("whitelist-dns")
    )
    c["processing"]["network"]["allowed_dns"] = (
        c["processing"]["network"].pop("allowed-dns")
    )
    c["routing"] = {
        "routing": c["cuckoo"].pop("routing"),
    }
    c["reporting"]["misp"] = {
        "enabled": False,
        "url": None,
        "apikey": None,
        "mode": "maldoc ipaddr",
    }
    if "url" not in c["reporting"]["notification"]:
        c["reporting"]["notification"]["url"] = None
    c["routing"]["routing"]["drop"] = False
    c["routing"]["inetsim"] = {
        "enabled": False,
        "server": "192.168.56.1",
    }
    c["routing"]["tor"] = {
        "enabled": False,
        "dnsport": 5353,
        "proxyport": 9040,
    }
    # Merges the main VPN settings and all of the defined VPN entries.
    c["routing"].update(c.pop("vpn"))
    c["vsphere"]["vsphere"]["unverified_ssl"] = False
    return c

migrations = {
    "0.4": ("0.4.1", _040_041),
    "0.4.1": ("0.4.2", _041_042),
    "0.4.2": ("0.5.0", _042_050),
    "0.5.0": ("0.6.0", _050_060),
    "0.6.0": ("1.0.0", _060_100),
    "1.0.0": ("1.1.0", _100_110),
    "1.1.0": ("1.2.0", _110_120),
    "1.2.0": ("2.0-rc1", _120_20c1),
    "2.0-rc1": ("2.0-rc2", _20c1_20c2),
    "2.0-rc2": ("2.0.0", _20c2_200),
}

def migrate(c, current, to):
    """Upgrade the configuration 'c' from 'current' to 'to'."""
    while current != to:
        current, migration = migrations[current]
        c = migration(c)
    return c
