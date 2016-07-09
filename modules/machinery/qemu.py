# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import time
import logging
import subprocess
import os.path

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)

# this whole semi-hardcoded commandline thing is not the best
#  but in the config files we can't do arrays etc so we'd have to parse the
#  configured commandlines somehow and then fill in some more things
#  anyways, if someone has a cleaner suggestion for this, let me know
#  -> for now, just modify this to your needs
QEMU_ARGS = {
    "default": {
        "cmdline": ["qemu-system-x86_64", "-display", "none"],
        "params": {
            "memory": "512M",
            "mac": "52:54:00:12:34:56",
            "kernel": "{imagepath}/vmlinuz",
        },
    },
    "mipsel": {
        "cmdline": [
            "qemu-system-mipsel", "-display", "none", "-M", "malta", "-m", "{memory}",
            "-kernel", "{kernel}",
            "-hda", "{snapshot_path}",
            "-append", "root=/dev/sda1 console=tty0",
            "-netdev", "tap,id=net_{vmname},ifname=tap_{vmname}",
            "-device", "e1000,netdev=net_{vmname},mac={mac}",  # virtio-net-pci doesn't work here
        ],
        "params": {
            "kernel": "{imagepath}/vmlinux-3.2.0-4-4kc-malta-mipsel",
        }
    },
    "mips": {
        "cmdline": [
            "qemu-system-mips", "-display", "none", "-M", "malta", "-m", "{memory}",
            "-kernel", "{kernel}",
            "-hda", "{snapshot_path}",
            "-append", "root=/dev/sda1 console=tty0",
            "-netdev", "tap,id=net_{vmname},ifname=tap_{vmname}",
            "-device", "e1000,netdev=net_{vmname},mac={mac}",  # virtio-net-pci doesn't work here
        ],
        "params": {
            "kernel": "{imagepath}/vmlinux-3.2.0-4-4kc-malta-mips",
        }
    },
    "armwrt": {
        "cmdline": [
            "qemu-system-arm", "-display", "none", "-M", "realview-eb-mpcore", "-m", "{memory}",
            "-kernel", "{kernel}",
            "-drive", "if=sd,cache=unsafe,file={snapshot_path}",
            "-append", "console=ttyAMA0 root=/dev/mmcblk0 rootwait",
            "-net", "tap,ifname=tap_{vmname}", "-net", "nic,macaddr={mac}",  # this by default needs /etc/qemu-ifup to add the tap to the bridge, slightly awkward
        ],
        "params": {
            "kernel": "{imagepath}/openwrt-realview-vmlinux.elf",
        }
    },
    "arm": {
        "cmdline": [
            "qemu-system-arm", "-display", "none", "-M", "versatilepb", "-m", "{memory}",
            "-kernel", "{kernel}", "-initrd", "{initrd}",
            "-hda", "{snapshot_path}",
            "-append", "root=/dev/sda1",
            "-net", "tap,ifname=tap_{vmname}", "-net", "nic,macaddr={mac}",  # this by default needs /etc/qemu-ifup to add the tap to the bridge, slightly awkward
        ],
        "params": {
            "memory": "256M",  # 512 didn't work for some reason
            "kernel": "{imagepath}/vmlinuz-3.2.0-4-versatile-arm",
            "initrd": "{imagepath}/initrd-3.2.0-4-versatile-arm",
        }
    },
    "x64": {
        "cmdline": [
            "qemu-system-x86_64", "-display", "none", "-m", "{memory}",
            "-hda", "{snapshot_path}",
            "-net", "tap,ifname=tap_{vmname}", "-net", "nic,macaddr={mac}",  # this by default needs /etc/qemu-ifup to add the tap to the bridge, slightly awkward
        ],
        "params": {
            "memory": "1024M",
        }
    },
    "x86": {
        "cmdline": [
            "qemu-system-i386", "-display", "none", "-m", "{memory}",
            "-hda", "{snapshot_path}",
            "-net", "tap,ifname=tap_{vmname}", "-net", "nic,macaddr={mac}",  # this by default needs /etc/qemu-ifup to add the tap to the bridge, slightly awkward
        ],
        "params": {
            "memory": "1024M",
        }
    },
}

class QEMU(Machinery):
    """Virtualization layer for QEMU (non-KVM)."""

    # VM states.
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "machete"

    def __init__(self):
        super(QEMU, self).__init__()
        self.state = {}

    def _initialize_check(self):
        """Runs all checks when a machine manager is initialized.
        @raise CuckooMachineError: if QEMU binary is not found.
        """
        # VirtualBox specific checks.
        if not self.options.qemu.path:
            raise CuckooCriticalError("QEMU binary path missing, "
                                      "please add it to the config file")
        if not os.path.exists(self.options.qemu.path):
            raise CuckooCriticalError("QEMU binary not found at "
                                      "specified path \"%s\"" %
                                      self.options.qemu.path)

        self.qemu_dir = os.path.dirname(self.options.qemu.path)
        self.qemu_img = os.path.join(self.qemu_dir, "qemu-img")

    def start(self, label, task):
        """Start a virtual machine.
        @param label: virtual machine label.
        @param task: task object.
        @raise CuckooMachineError: if unable to start.
        """
        log.debug("Starting vm %s" % label)

        vm_info = self.db.view_machine_by_label(label)
        vm_options = getattr(self.options, vm_info.name)

        snapshot_path = os.path.join(os.path.dirname(vm_options.image), vm_info.name) + ".qcow2"
        if os.path.exists(snapshot_path):
            os.remove(snapshot_path)

        # make sure we use a new harddisk layer by creating a new qcow2 with backing file
        try:
            proc = subprocess.Popen([self.qemu_img, "create", "-f", "qcow2", "-b", vm_options.image, snapshot_path],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, err = proc.communicate()
            if err:
                raise OSError(err)
        except OSError as e:
            raise CuckooMachineError("QEMU failed starting the machine: %s" % e)

        vm_arch = getattr(vm_options, "arch", "default")
        arch_config = dict(QEMU_ARGS[vm_arch])
        cmdline = arch_config["cmdline"]
        params = dict(QEMU_ARGS["default"]["params"])
        params.update(QEMU_ARGS[vm_arch]["params"])

        params.update({
            "imagepath": os.path.dirname(vm_options.image),
            "snapshot_path": snapshot_path,
            "vmname": vm_info.name,
        })

        # allow some overrides from the vm specific options
        # also do another round of parameter formatting
        for var in ["mac", "kernel", "initrd"]:
            val = getattr(vm_options, var, params.get(var, None))
            if not val:
                continue
            params[var] = val.format(**params)

        # magic arg building
        final_cmdline = [i.format(**params) for i in cmdline]

        log.debug("Executing QEMU %r", final_cmdline)

        try:
            proc = subprocess.Popen(final_cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.state[vm_info.name] = proc
        except OSError as e:
            raise CuckooMachineError("QEMU failed starting the machine: %s" % e)

    def stop(self, label):
        """Stops a virtual machine.
        @param label: virtual machine label.
        @raise CuckooMachineError: if unable to stop.
        """
        log.debug("Stopping vm %s" % label)

        vm_info = self.db.view_machine_by_label(label)

        if self._status(vm_info.name) == self.STOPPED:
            raise CuckooMachineError("Trying to stop an already stopped vm %s" % label)

        proc = self.state.get(vm_info.name, None)
        proc.kill()

        stop_me = 0
        while proc.poll() is None:
            if stop_me < int(self.options_globals.timeouts.vm_state):
                time.sleep(1)
                stop_me += 1
            else:
                log.debug("Stopping vm %s timeouted. Killing" % label)
                proc.terminate()
                time.sleep(1)

        # if proc.returncode != 0 and stop_me < int(self.options_globals.timeouts.vm_state):
        #     log.debug("QEMU exited with error powering off the machine")

        self.state[vm_info.name] = None

    def _status(self, name):
        """Gets current status of a vm.
        @param name: virtual machine name.
        @return: status string.
        """
        p = self.state.get(name, None)
        if p is not None:
            return self.RUNNING
        return self.STOPPED
