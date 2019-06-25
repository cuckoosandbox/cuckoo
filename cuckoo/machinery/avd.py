# Copyright (C) 2015-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import os
import time
import socket
import logging
import subprocess

from cuckoo.common.abstracts import Machinery
from cuckoo.common.exceptions import CuckooCriticalError, CuckooMachineError

log = logging.getLogger(__name__)

class Avd(Machinery):
    """Virtualization layer for Android Emulator."""

    def _initialize_check(self):
        """Run all checks when a machine manager is initialized.
        @raise CuckooMachineError: if the android emulator is not found.
        """
        self._emulators = {}

        if not self.options.avd.emulator_path:
            raise CuckooCriticalError(
                "emulator path missing, please add it to the config file"
            )

        if not os.path.exists(self.options.avd.emulator_path):
            raise CuckooCriticalError(
                "emulator not found at specified path \"%s\""
                % self.options.avd.emulator_path
            )

        if not self.options.avd.adb_path:
            raise CuckooCriticalError(
                "adb path missing, please add it to the config file"
            )

        if not os.path.exists(self.options.avd.adb_path):
            raise CuckooCriticalError(
                "adb not found at specified path \"%s\""
                % self.options.avd.adb_path
            )

        try:
            # Restart the adb server.
            subprocess.check_call([
                self.options.avd.adb_path, "kill-server"
            ])

            subprocess.check_call([
                self.options.avd.adb_path, "start-server"
            ])
        except subprocess.CalledProcessError as e:
            log.error("Unable to restart the adb server: %s", e)

    def start(self, label, task):
        """Start a virtual machine.
        @param label: virtual machine name.
        @param task: task object.
        """
        log.debug("Starting vm %s", label)

        try:
            args = [
                self.options.avd.emulator_path,
                "@%s" % label,
                "-no-snapshot-save",
                "-netspeed", "full",
                "-netdelay", "none",
                "-tcpdump", self.pcap_path(task.id)
            ]

            # In headless mode we remove the audio, and window support.
            if self.options.avd.mode == "headless":
                args += ["-no-audio", "-no-window"]

            # If a proxy address has been provided for this analysis, then we have
            # to pass the proxy address along to the emulator command. The
            # mitmproxy instance is not located at the resultserver's IP address
            # though, so we manually replace the IP address by localhost.
            if "proxy" in task.options:
                _, port = task.options["proxy"].split(":")
                args += ["-http-proxy", "http://127.0.0.1:%s" % port]

            # Retrieve snapshot name for this machine to load it.
            for machine in self.machines():
                if machine.label == label:
                    args += ["-snapshot", machine.snapshot]
                    break

            # Create a socket server to receive the console port of the emulator.
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", 0))
            s.listen(5)

            args += ["-report-console", "tcp:" + str(s.getsockname()[1])]

            # Start the emulator process..
            subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            console_port = s.accept()[0].recv(1024)
        except OSError as e:
            raise CuckooMachineError(
                "Emulator failed starting machine %s: %s" % (label, e)
            )
        finally:
            s.close()

        self._emulators[label] = "emulator-" + console_port
        self._wait_status_ready(label)

    def _wait_status_ready(self, label):
        """Wait for an emulator to become ready.
        @param label: virtual machine name.
        """
        log.debug(
            "Waiting for machine %s to become available.", label
        )

        try:
            args = [
                self.options.avd.adb_path,
                "-s", self._emulators[label],
                "wait-for-device"
            ]
            subprocess.check_call(args)
        except subprocess.CalledProcessError as e:
            raise CuckooMachineError(
                "Failed to issue adb command: %s" % e
            )

    def stop(self, label):
        """Stop a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to stop.
        """
        log.debug("Stopping vm %s", label)

        try:
            args = [
                self.options.avd.adb_path,
                "-s", self._emulators[label],
                "emu", "kill"
            ]
            subprocess.check_call(args)
        except subprocess.CalledProcessError as e:
            raise CuckooMachineError(
                "Emulator failed stopping the machine: %s" % e
            )

        del self._emulators[label]

    def port_forward(self, label, dport):
        """Configure port forwarding for a vm.
        @param label: virtual machine name.
        @param dport: destination port on the vm.
        @return: host forwarding port.
        @raise CuckooMachineError: if unable to set up forwarding.
        """
        try:
            args = [
                self.options.avd.adb_path,
                "-s", self._emulators[label],
                "forward", "tcp:0", "tcp:%s" % dport
            ]
            p = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            output, err = p.communicate()

            if p.returncode:
                raise OSError(err)
        except OSError as e:
            raise CuckooMachineError(
                "Adb failed to set up port forwarding: %s" % e
            )

        return int(output.splitlines()[0])
