# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import re
import time
import logging
import subprocess
import os.path

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)

QEMU_ARGS = {
    "default": {
        "args": {
            "-display": "none",
            "-m": "1024M",
            "-smp": "cpus=2",
            "-hda": "{snapshot_path}", # will be replaced with the real thing
            "-netdev": "bridge,id=net1,br=qemubr",
            "-device": "virtio-net-pci,romfile=,netdev=net1",
        }
    },
    "mipsel": {
        "binary": "qemu-system-mipsel",
        "kernel": "vmlinux-3.2.0-4-4kc-malta",
        "args": {
            "-M": "malta",
            "-smp": "cpus=1",
            "-append": "root=/dev/sda1 console=tty0",
            "-device": "e1000,netdev=net1", # virtio-net-pci doesn't work here
            "-kernel": "{imagepath}/{kernel}", # we assume the kernel is in the same place as the hdd image
        }
    }
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

    def start(self, label):
        """Start a virtual machine.
        @param label: virtual machine label.
        @raise CuckooMachineError: if unable to start.
        """
        log.debug("Starting vm %s" % label)

        vm_info = self.db.view_machine_by_label(label)
        vm_options = getattr(self.options, vm_info.name)

        snapshot_path = os.path.join(os.path.dirname(vm_options.image), vm_info.name) + ".qcow2"
        if os.path.exists(snapshot_path): os.remove(snapshot_path)

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
        qemu_args_config = dict(QEMU_ARGS[vm_arch])
        qemu_args_config["args"] = dict(QEMU_ARGS["default"]["args"])
        qemu_args_config["args"].update(QEMU_ARGS[vm_arch]["args"])

        format_params = {
            "imagepath": os.path.dirname(vm_options.image),
            "kernel": qemu_args_config.get("kernel", ""),
            "snapshot_path": snapshot_path,
        }

        if vm_options.kernel:
            qemu_args_config["args"]["-kernel"] = vm_options.kernel.format(**format_params)

        if vm_options.mac:
            qemu_args_config["args"]["-device"] += ",mac=%s" % vm_options.mac

        # replace net1 with the vm name, there's something funky when qemu runs several vms with the same id there
        qemu_args_config["args"]["-netdev"] = qemu_args_config["args"]["-netdev"].replace("id=net1", "id=%s" % vm_info.name)
        qemu_args_config["args"]["-device"] = qemu_args_config["args"]["-device"].replace("netdev=net1", "netdev=%s" % vm_info.name)

        if "binary" in qemu_args_config:
            qemu_binary = os.path.join(self.qemu_dir, qemu_args_config["binary"])
        else:
            qemu_binary = self.options.qemu.path

        # magic arg building
        qemu_args = [qemu_binary,] + reduce(lambda x,y: x + [y[0], y[1].format(**format_params)], qemu_args_config["args"].iteritems(), [])

        log.debug("Executing QEMU %r", qemu_args)

        try:
            proc = subprocess.Popen(qemu_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
        if p != None:
            return self.RUNNING
        return self.STOPPED
