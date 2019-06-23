# Copyright (C) 2015-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import os
import time
import logging
import subprocess

from cuckoo.common.abstracts import Machinery
from cuckoo.common.exceptions import CuckooCriticalError, CuckooMachineError

log = logging.getLogger(__name__)

class Avd(Machinery):
    """Virtualization layer for Android Emulator."""

    def _initialize_check(self):
        """Runs all checks when a machine manager is initialized.
        @raise CuckooMachineError: if the android emulator is not found.
        """
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

        args = [
            self.options.avd.emulator_path,
            "@%s" % label,
            "-snapshot", self.options[label].snapshot,
            "-no-snapshot-save",
            "-delay-adb",
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

        # Start the emulator process..
        subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        # Wait untill the emulator shows up for the adb server.
        while True:
            if self._device_serial(label):
                break

            log.debug(
                "Waiting for machine %s to become available.", label
            )
            time.sleep(1)

        log.debug("Emulator has been found!")

    def stop(self, label):
        """Stops a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to stop.
        """
        log.debug("Stopping vm %s", label)

        args = [
            self.options.avd.adb_path,
            "-s", self._device_serial(label),
            "emu", "kill"
        ]

        try:
            subprocess.check_call(args)
        except subprocess.CalledProcessError as e:
            raise CuckooMachineError(
                "Emulator failed killing the machine: %s" % e
            )

    def _list(self):
        """Lists virtual machines installed.
        @return: virtual machine names list.
        """
        args = [
            self.options.avd.emulator_path, "-list-avds"
        ]

        try:
            output, _ = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            ).communicate()
        except OSError as e:
            raise CuckooMachineError(
                "Emulator failed listing machines: %s" % e
            )

        machines = []
        for label in output.splitlines():
            machines.append(label)
        return machines

    def _status(self, label):
        """Gets current status of a vm.
        @param label: virtual machine name.
        @return: status string.
        """
        log.debug("Getting status for %s", label)

    def _device_serial(self, label):
        """Returns the virtual device serial of the given label.
        @param label: virtual machine name.
        @return: device serial as seen by adb.
        """
        args = [
            self.options.avd.adb_path,
            "devices"
        ]

        try:
            output, _ = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            ).communicate()
        except OSError as e:
            log.critical(
                "Failed to retrieve currently running devices: %s", e
            )
            return

        for line in output.splitlines()[1:-1]:
            device_serial = line.split('\t')[0]
            args = [
                self.options.avd.adb_path,
                "-s", device_serial,
                "emu", "avd", "name"
            ]

            try:
                output, err = subprocess.Popen(
                    args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                ).communicate()
                if err:
                    raise OSError(err)
            except OSError as e:
                log.error(
                    "Failed to retrieve name of virtual device: %s", e
                )
                continue
            
            if output.splitlines()[0] == label:
                return device_serial

    def port_forward(self, label, dport):
        """Configures port forwarding for a vm.
        @param label: virtual machine name.
        @param dport: destination port on the vm.
        @return: host forwarding port.
        @raise CuckooMachineError: if unable to set up forwarding.
        """
        args = [
            self.options.avd.adb_path,
            "-s", self._device_serial(label),
            "forward", "tcp:0", "tcp:%s" % dport
        ]

        try:
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
