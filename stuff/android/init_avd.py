#!/usr/bin/env python3
# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

#
# This script is responsible for setting up an Android virtual device to be
# used for analysis by Cuckoo.
#
# Objectives:
#    1- Creating an Android virtual device.
#    2- Initializing the host network bridge.
#    3- Configuring the networking inside the guest.
#    4- Downloading and pushing our prebuilt Python interpreter.
#    5- Installing helper files & APKs.
#    6- Installing and starting the Cuckoo agent.
#    7- Saving a snapshot of the virtual device state.
#    8- Configuring the cuckoo working directory to add a new machine.
#
#    NOTE: for this script to work properly, make sure the cwd is initialized.
#

import re
import os
import sys
import time
import shutil
import random
import tarfile
import getpass
import logging
import tempfile
import argparse
import ipaddress
import subprocess
import configparser
import urllib.request

SUPPORTED_ANDROID_ABIS = ["x86", "x86_64", "armeabi-v7a", "armeabi", "arm64-v8a"]
MINIMUM_ANDROID_API_LEVEL = 21

PREBUILT_PY_URL = "https://github.com/muhzii/community/raw/master/prebuilt/Python3.7/android-%s.tar.gz"
FAKE_CONTACTS_APP_URL = "https://github.com/cuckoosandbox/cuckoo/raw/master/stuff/android/apps/ImportContacts.apk"
FAKE_DRIVERS_URL = "https://github.com/cuckoosandbox/cuckoo/raw/master/stuff/android/anti-vm/fake-drivers"
FAKE_CPUINFO_URL = "https://github.com/cuckoosandbox/cuckoo/raw/master/stuff/android/anti-vm/fake-cpuinfo"

HOST_BRIDGE_IFACE_IP = "10.3.2.1"

sh = logging.StreamHandler()
sh.setFormatter(
    logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
)
logging.getLogger().addHandler(sh)
logging.getLogger().setLevel(logging.INFO)

log = logging.getLogger("init_avd")


def download_file(url, dest_dir):
    """Download the file at the given URL to the specified directory"""
    filename = url[url.rfind("/") + 1:]

    conn = urllib.request.urlopen(url)
    with open(os.path.join(dest_dir, filename), "wb") as out:
        out.write(conn.read())

    log.info("Successfully downloaded file: %s" % filename)
    return os.path.join(dest_dir, filename)


def run_cmd(args):
    """Run a command and return the results."""
    try:
        proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, err = proc.communicate()
        if proc.returncode != 0:
            raise OSError(err)
    except OSError as e:
        log.error(e)
        sys.exit(1)

    return str(out, "utf-8")


class Adb(object):
    """Adb commands wrapper."""

    def __init__(self, adb_path, emulator_label):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.adb_prefix = [adb_path, "-s", emulator_label]

    def cmd(self, args):
        return run_cmd(self.adb_prefix + args)

    def install(self, path_to_apk):
        run_cmd(self.adb_prefix + ["install", path_to_apk])

    def shell(self, args):
        return run_cmd(self.adb_prefix + ["shell"] + args)

    def root(self):
        run_cmd(self.adb_prefix + ["root"])

    def emu(self, args):
        return run_cmd(self.adb_prefix + ["emu"] + args)

    def push(self, src, dest="/data/local/tmp"):
        run_cmd(self.adb_prefix + ["push", src, dest])
        self.logger.info(
            "Successfully transfered file: %s, to the device "
            "in: %s" % (src, dest)
        )

    def uninstall(self, pkg_name):
        run_cmd(self.adb_prefix + ["uninstall", pkg_name])


class VM_SPECS(object):
    def __init__(self, vmname, sdcard_size, abi, api_level, hw_skin, mode):
        self.vmname = vmname
        self.sdcard_size = sdcard_size
        self.abi = abi

        self.arch = self.determine_device_arch()
        if not self.arch:
            log.error("ERROR: failed to determine device architecture")
            sys.exit(1)

        self.api_level = api_level
        self.hw_skin = hw_skin
        self.mode = mode

    def determine_device_arch(self):
        """Decide the architecture of the vm based on the ABI."""
        supported_archs = ["arm64", "arm", "x86_64", "x86"]
        for arch in supported_archs:
            if arch in self.abi:
                return arch


class AvdCwdConfigManager(object):
    "Configures a cuckoo working directory for Android."

    def __init__(self, cwd_path):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.config_filepath = os.path.abspath(
            os.path.expanduser(os.path.join(cwd_path, "conf"))
        )

    def get_config(self, filename):
        """Get the configurations of a cwd conf file.
        @return ConfigParser object.
        """
        cfg = configparser.ConfigParser()
        cfg.read(os.path.join(self.config_filepath, filename))
        return cfg

    def write_config(self, filename, config):
        """Write the configurations to the specified cwd conf file."""
        with open(os.path.join(self.config_filepath, filename), "w") as configfile:
            config.write(configfile)

    def get_android_machines(self):
        """Get all configured Avd machines
        @return: a list of machine names.
        """
        machines = self.get_config("avd.conf")["avd"]["machines"].split(", ")
        return machines if machines[0] else []

    def add_new_android_machine(self, vmname, vm_ip, vmmode):
        """Add configuration for a new Android virtual machine."""
        self.logger.info(
            "Configuring the cuckoo working directory for the vm: %s"
            ", IP: %s.", vmname, vm_ip
        )

        avd_config = self.get_config("avd.conf")
        machines = [vmname] + self.get_android_machines()
        avd_config["avd"]["machines"] = ", ".join(machines)
        avd_config[vmname] = {}
        avd_config[vmname]["label"] = vmname
        avd_config[vmname]["platform"] = "android"
        avd_config[vmname]["ip"] = vm_ip
        avd_config[vmname]["snapshot"] = "cuckoo_snapshot"
        avd_config[vmname]["resultserver_ip"] = ""
        avd_config[vmname]["resultserver_port"] = ""
        avd_config[vmname]["options"] = "headless"
        avd_config[vmname]["osprofile"] = ""

        self.write_config("avd.conf", avd_config)

    def ensure_default_configs(self, emulator_path, adb_path):
        """Ensure the default configurations are in place for a running
        Cuckoo Android instance."""
        # Configure the cuckoo.conf for Avd and the resultserver
        cuckoo_config = self.get_config("cuckoo.conf")
        cuckoo_config["resultserver"]["ip"] = HOST_BRIDGE_IFACE_IP
        cuckoo_config["cuckoo"]["machinery"] = "avd"

        if self.get_config("cuckoo.conf") != cuckoo_config:
            self.write_config("cuckoo.conf", cuckoo_config)

        # Configure the paths of the executables for the emulator & adb
        avd_config = self.get_config("avd.conf")
        avd_config["avd"]["adb_path"] = adb_path
        avd_config["avd"]["emulator_path"] = emulator_path

        if self.get_config("avd.conf") != avd_config:
            self.write_config("avd.conf", avd_config)


class AvdFactory(object):
    """Creates and Prepares an Android virtual device."""

    def __init__(self, android_sdk_path, cwd_path):
        self.logger = logging.getLogger(self.__class__.__name__)

        self.cwd_path = cwd_path
        self.avdmanager_path = os.path.join(android_sdk_path, "tools", "bin", "avdmanager")
        self.sdkmanager_path = os.path.join(android_sdk_path, "tools", "bin", "sdkmanager")
        self.emulator_path = os.path.join(android_sdk_path, "emulator", "emulator")
        self.adb_path = os.path.join(android_sdk_path, "platform-tools", "adb")

        self.hardware_skins = []
        out = run_cmd([self.avdmanager_path, "list", "device"])
        for skin_name in re.findall(r"(?<=\").*(?=\")", out):
            self.hardware_skins.append(skin_name)

        self.adb = None
        self.wdir = None
        self.vm_ip = None
        self.dev_specs = None
        self.image_pkg_name = None
        self.has_router_net_namespace = False

    def read_avd_specs(self):
        """Reads the specs of the virtual device to create from user input.
        return: VM_SPECS object.
        """
        vmname = input("Specify the name of the virtual device: ")
        if not vmname:
            self.logger.error("You need to specify a name for the new virtual device.")
            sys.exit(1)
        elif vmname in AvdCwdConfigManager(self.cwd_path).get_android_machines():
            self.logger.error("A machine with this name already exists.")
            sys.exit(1)

        sdcard_size = input("Specify size of sdcard in megabytes [500]: ")
        if not sdcard_size:
            sdcard_size = 500

        android_abi = input(
            "Select the Android ABI (x86, x86_64, armeabi-v7a, arm64-v8a): "
        )
        if not android_abi in SUPPORTED_ANDROID_ABIS:
            self.logger.error("Incorrect input for Android ABI.")
            sys.exit(1)

        android_api_level = input("Specify the Android API level (>= 21): ")
        if not android_api_level or not android_api_level.isdigit() or \
            int(android_api_level) < MINIMUM_ANDROID_API_LEVEL:
            self.logger.error(
                "Incorrect or unsupported Android API version. Make sure "
                "to select an appropiate API level (>= 21 -- Lollipop)."
            )
            sys.exit(1)

        hw_skin = input(
            "Select a hardware skin for the virtual device. "
            "Available options:\n%s [pixel]: " % "\n".join(self.hardware_skins)
        )
        if not hw_skin:
            hw_skin = "pixel"
        elif hw_skin not in self.hardware_skins:
            self.logger.error("invalid choice for device hardware definition.")
            sys.exit(1)

        vmmode = input("Select vm rendering mode (gui, headless) [headless]: ")
        if not vmmode:
            vmmode = "headless"
        elif vmmode not in ("gui", "headless"):
            self.logger.error("invalid choice for vm rendering mode")
            sys.exit(1)

        self.dev_specs = VM_SPECS(
            vmname, sdcard_size, android_abi, android_api_level, hw_skin, vmmode
        )

        self.image_pkg_name = "system-images;android-%s;default;%s" % \
                              (android_api_level, android_abi)

    def install_python(self):
        """Download and install the prebuilt Python interpreter for Android."""
        self.logger.info(
            "Downloading the prebuilt Python interpreter for the device.."
        )
        tar_filepath = download_file(PREBUILT_PY_URL % self.dev_specs.arch, self.wdir)
        with tarfile.open(tar_filepath) as tar:
            tar.extractall(self.wdir)

        self.logger.info("Copying the Python interpreter to the device.")
        self.adb.push(os.path.join(self.wdir, "usr"))

    def install_fake_contacts(self):
        """Download and install the contacts Application"""
        self.logger.info("Downloading the contacts generator app..")
        contacts_app_filepath = download_file(FAKE_CONTACTS_APP_URL, self.wdir)

        self.logger.info("Generating fake contacts in the device..")
        self.adb.install(contacts_app_filepath)
        self.adb.shell(["am", "start", "-n", "com.amossys.hooker.generatecontacts/.ImportContacts"])
        self.adb.cmd(["logcat", "-m4", "-s", "GenerateContacts"])
        self.adb.uninstall("com.amossys.hooker.generatecontacts")

    def install_fake_drivers(self):
        """Push fake drivers to the virtual device"""
        self.logger.info("Downloading files for fake drivers..")
        drivers_filepath = download_file(FAKE_DRIVERS_URL, self.wdir)

        self.logger.info("Copying fake drivers to the virtual device..")
        self.adb.push(drivers_filepath)

    def install_fake_cpuinfo(self):
        """Push fake drivers to the virtual device"""
        self.logger.info("Downloading files for fake cpuinfo..")
        cpuinfo_filepath = download_file(FAKE_CPUINFO_URL, self.wdir)

        self.logger.info("Copying fake cpuinfo to the virtual device..")
        self.adb.push(cpuinfo_filepath)

    def install_cuckoo_agent(self):
        """Install and start the cuckoo agent inside the vm"""
        self.logger.info("Copying the agent files to the virtual device..")
        self.adb.push(os.path.join(self.cwd_path, "agent", "agent.py"))
        self.adb.push(os.path.join(self.cwd_path, "agent", "android-agent.sh"))

        self.logger.info("Starting the cuckoo agent process..")
        self.adb.shell(["chmod", "06755", "/data/local/tmp/android-agent.sh"])

        if self.has_router_net_namespace:
            self.adb.shell([
                "ip", "netns", "exec", "router", "/data/local/tmp/android-agent.sh"
            ])
        else:
            self.adb.shell(["/data/local/tmp/android-agent.sh"])

    def setup_guest_networking(self):
        """Setup the networking inside the guest with the host bridge."""
        machines = AvdCwdConfigManager(self.cwd_path).get_android_machines()
        ip_addr = ipaddress.ip_address(HOST_BRIDGE_IFACE_IP) + len(machines) + 1
        self.vm_ip = ip_addr.compressed

        mac_addr = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                    random.randint(0, 255),
                    random.randint(0, 255))

        # The networking setup in the Android OS may vary between different
        # versions of the system image.
        ifaces = re.findall(r"(?<=: ).*(?=: )", self.adb.shell(["ip", "a"]))
        if "eth0" in ifaces:
            #
            #    main namespace
            #
            #   ----------------
            #  | eth0 (default) |
            #   ----------------
            #  - ip: 10.3.2.xxx
            #  - gw: 10.3.2.1 (ip of the host bridge)
            #
            
            # Configure the eth0 default interface.
            self.adb.shell(["ip", "link", "set", "eth0", "down"])
            self.adb.shell(["ip", "addr", "flush", "dev", "eth0"])
            self.adb.shell(["ifconfig", "eth0", self.vm_ip])
            self.adb.shell([
                "ndc", "network", "route", "add", "100", "eth0", "0.0.0.0/0",
                HOST_BRIDGE_IFACE_IP
            ])
            self.adb.shell(["ip", "link", "set", "eth0", "address", mac_addr])
            self.adb.shell(["ip", "link", "set", "eth0", "up"])
        else:
            #
            #    main namespace     |           router namespace
            #                       |
            #   -----------------   |     -------
            #  | wlan0 (default) |--+--->| wlan1 |--------------|
            #   -----------------   |     -------               |
            #  - ip: 192.168.232.2  |    - ip: 192.168.232.1    |
            #  - gw: 192.168.232.1  |                           |
            #                       |      ------               |
            #                       |     | eth0 |<-------------|
            #                       |      ------
            #                       |     - ip: 10.3.2.xxx
            #                       |     - gw: 10.3.2.1 (ip of the host bridge)
            #                       |
            self.has_router_net_namespace = True

            # Bring up the loopback interface inside the router namespace.
            # (Needed for the Android analyzer to be able to reach the agent).
            self.adb.shell([
                "ip", "netns", "exec", "router", "ifconfig", "lo", "127.0.0.1"
            ])
            self.adb.shell([
                "ip", "netns", "exec", "router", "ip", "link", "set", "lo", "up"
            ])

            # Configure the eth0 interface.
            self.adb.shell([
                "ip", "netns", "exec", "router", "ip", "link", "set", "eth0", "down"
            ])
            self.adb.shell([
                "ip", "netns", "exec", "router", "ip", "addr", "flush", "dev", "eth0"
            ])
            self.adb.shell([
                "ip", "netns", "exec", "router", "ifconfig", "eth0", self.vm_ip
            ])
            self.adb.shell([
                "ip", "netns", "exec", "router", "ip", "route", "add", "default",
                "via", HOST_BRIDGE_IFACE_IP, "dev", "eth0"
            ])
            self.adb.shell([
                "ip", "netns", "exec", "router", "ip", "link", "set", "eth0",
                "address", mac_addr
            ])
            self.adb.shell([
                "ip", "netns", "exec", "router", "ip", "link", "set", "eth0", "up"
            ])

        # Configure the DNS for the default network (netId 100).
        self.adb.shell([
            "ndc", "resolver", "setnetdns", "100", "\"\"", "8.8.8.8", "8.8.8.4"
        ])

    def start_emulator(self):
        """Start the Android emulator and wait untill it fully boots up."""
        self.logger.info("Starting the Android emulator..")
        args = [
            self.emulator_path,
            "@%s" % self.dev_specs.vmname,
            "-net-tap", "tap_%s" % self.dev_specs.vmname,
            "-net-tap-script-up",
            os.path.join(self.cwd_path, "stuff", "setup-hostnet-avd.sh")
        ]

        # In headless mode we remove the audio, and window support.
        if self.dev_specs.mode == "headless":
            args += ["-no-audio", "-no-window"]

        proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        self.logger.info("Waiting for the emulator to become available..")
        found = False
        while True:
            if proc.poll() is not None:
                out, err = proc.communicate()
                exc_info = ""
                for line in out.decode().splitlines():
                    if "emulator: ERROR: " in line:
                        exc_info += "%s\n" % line
                exc_info += err.decode()

                self.logger.error(
                    "Failed to start the Android emulator: %s" % exc_info
                )
                sys.exit(1)

            emulators = re.findall(
                r"emulator-[0-9]*", run_cmd([self.adb_path, "devices"])
            )
            for emulator_label in emulators:
                adb = Adb(self.adb_path, emulator_label)
                if self.dev_specs.vmname in adb.emu(["avd", "name"]):
                    self.adb = adb
                    found = True
                    break

            if found:
                break

            time.sleep(1)

        self.logger.info("Waiting for the vm to finish booting up..")
        self.adb.cmd(["wait-for-device"])
        boot_stages = [
            "dev.bootcomplete", "sys.boot_completed", "init.svc.bootanim"
        ]
        boot_props = ["1", "1", "stopped"]
        curr_stage = 0
        while curr_stage < 3:
            cur_prop_value = self.adb.shell(["getprop", boot_stages[curr_stage]])
            if boot_props[curr_stage] in cur_prop_value:
                self.logger.info(" - (%s)", boot_stages[curr_stage])
                curr_stage += 1

            time.sleep(1)

    def stop_emulator(self):
        """Stop the Android emulator."""
        self.logger.info("Stopping the Android emulator..")
        self.adb.emu(["kill"])

    def create_avd(self):
        """Create a new Android virtual device."""
        self.logger.info("Installing the Android system image..")
        run_cmd([self.sdkmanager_path, "--install", self.image_pkg_name])

        self.logger.info(
            "Creating the virtual device with the specified settings.."
        )
        run_cmd([
            self.avdmanager_path, "create", "avd",
            "-n", self.dev_specs.vmname,
            "-c", "%sM" % self.dev_specs.sdcard_size,
            "-k", self.image_pkg_name,
            "-d", self.dev_specs.hw_skin
        ])

    def save_snapshot(self):
        """Save a snapshot of the current device state."""
        self.logger.info("Saving a snapshot of the device state..")
        self.adb.emu(["avd", "snapshot", "save", "cuckoo_snapshot"])

    def run(self, working_dir):
        self.wdir = working_dir

        # Gather the specification of the virtual device from user input
        self.read_avd_specs()

        # Create the virtual device
        self.create_avd()

        # Start the emulator process.
        self.start_emulator()

        # Obtain root privileges through adbd.
        self.adb.root()

        # Set SELinux policy to permissive on the device..
        # This is required for frida to work properly on some versions of Android.
        # https://github.com/frida/frida-core/tree/master/lib/selinux
        self.adb.shell(["setenforce", "0"])

        # Setup the networking for the guest
        self.setup_guest_networking()

        # Prepare the device with the necessary files.
        self.install_python()
        self.install_fake_contacts()
        self.install_fake_cpuinfo()
        self.install_fake_drivers()
        self.install_cuckoo_agent()

        # Save a snapshot of the device state
        self.save_snapshot()

        # Stop the Android emulator
        self.stop_emulator()


def check_android_sdk_path(sdk_path):
    if not os.path.isfile(os.path.join(sdk_path, "platform-tools", "source.properties")) or \
        not os.path.isfile(os.path.join(sdk_path, "tools", "source.properties")) or \
        not os.path.isfile(os.path.join(sdk_path, "emulator", "source.properties")):
        log.error(
            "Incorrect path for the Android SDK root folder. Make sure you have "
            "the latest SDK installed with your android_sdk pointing to the "
            "root folder of the SDK."
        )
        sys.exit(1)


def check_cwd_path(cwd_path):
    if not os.path.isfile(os.path.join(cwd_path, ".cwd")):
        log.error(
            "Incorrect path for cuckoo working directory, make sure your"
            "cwd_path is both correct and initialized."
        )
        sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Initialize Android virtual devices for Cuckoo analysis."
    )
    parser.add_argument("android_sdk", help="Path to the Android SDK folder")
    parser.add_argument("cwd", help="Path to the cuckoo working directory")

    options = parser.parse_args()
    check_android_sdk_path(options.android_sdk)
    check_cwd_path(options.cwd)
    return options


if __name__ == "__main__":
    # Require superuser privilges before running this script.
    if os.getuid() != 0:
        subprocess.call(["sudo", sys.executable, *sys.argv])
        sys.exit()

    # Parse command line options
    options = parse_args()
    android_sdk_path = options.android_sdk
    cwd_path = options.cwd

    # Create and initialize a virtual device
    tmpdir = tempfile.mkdtemp()
    try:
        avd_factory = AvdFactory(android_sdk_path, cwd_path)
        avd_factory.run(tmpdir)
    finally:
        shutil.rmtree(tmpdir)

    # Accordingly configure the cuckoo working directory
    cfg_mgr = AvdCwdConfigManager(cwd_path)
    cfg_mgr.ensure_default_configs(avd_factory.emulator_path, avd_factory.adb_path)
    cfg_mgr.add_new_android_machine(avd_factory.dev_specs.vmname, avd_factory.vm_ip, avd_factory.dev_specs.mode)

    # Add a NOPASSWD & SETENV policy for the emulator when being run as root.
    if not os.path.isfile("/etc/sudoers.d/emu-sudo-rules"):
        with open("/etc/sudoers.d/emu-sudo-rules", "w") as f:
            f.write(
                "ALL ALL=(ALL) NOPASSWD: %s, %s\n" % (avd_factory.emulator_path, avd_factory.adb_path)
            )
