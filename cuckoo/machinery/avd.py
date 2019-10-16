# Copyright (C) 2015-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import os
import time
import socket
import select
import logging
import subprocess

from cuckoo.common.abstracts import Machinery
from cuckoo.common.config import config
from cuckoo.common.exceptions import CuckooCriticalError, CuckooMachineError
from cuckoo.misc import cwd

log = logging.getLogger(__name__)

class Avd(Machinery):
    """Virtualization layer for Android Emulator."""

    def _initialize_check(self):
        """Run all checks when a machine manager is initialized.
        @raise CuckooMachineError: if the android emulator is not found.
        """
        self._emulator_labels = {}

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
            subprocess.check_call([self.options.avd.adb_path, "kill-server"])
            subprocess.check_call([self.options.avd.adb_path, "start-server"])
        except subprocess.CalledProcessError as e:
            log.error("Unable to restart the adb server: %s", e)

    def start(self, label, task):
        """Start a virtual machine.
        @param label: virtual machine name.
        @param task: task object.
        """
        log.debug("Starting vm %s", label)

        vmname = self.db.view_machine_by_label(label).name
        vm_state_timeout = config("cuckoo:timeouts:vm_state")

        try:
            args = [
                "sudo", self.options.avd.emulator_path,
                "@%s" % label,
                "-no-snapshot-save",
                "-net-tap", "tap_%s" % vmname,
                "-net-tap-script-up", cwd("stuff", "setup-hostnet-avd.sh")
            ]

            # Aggregate machine-specific options.
            for machine in self.machines():
                if machine.label == label:
                    # In headless mode we remove the audio, and window support.
                    if "headless" in machine.options:
                        args += ["-no-audio", "-no-window"]

                    # Retrieve the snapshot name for this machine to load it.
                    args += ["-snapshot", machine.snapshot]

                    break

            # Create a socket server to acquire the console port of the emulator.
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(0)
            s.bind(("127.0.0.1", 0))
            s.listen(0)
            args += ["-report-console", "tcp:%s" % s.getsockname()[1]]

            # Start the emulator process..
            emu_conn = None
            proc = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )

            rlist = [s]
            time_cnt = 0
            while True:
                if proc.poll() is not None:
                    out, err = proc.communicate()
                    # Grab emulator error message from stderr & stdout
                    exc_info = ""
                    for line in out.splitlines():
                        if "emulator: ERROR: " in line:
                            exc_info += "%s\n" % line
                    exc_info += err

                    raise OSError(exc_info.rstrip())

                rds, _, _ = select.select(rlist, [], [], 0)
                sock2read = rds.pop() if rds else None
                if sock2read == s:
                    emu_conn, _ = s.accept()
                    emu_conn.setblocking(0)
                    rlist[0] = emu_conn
                elif emu_conn and sock2read == emu_conn:
                    emu_port = emu_conn.recv(1024)
                    break

                if time_cnt < vm_state_timeout:
                    time.sleep(1)
                    time_cnt += 1
                else:
                    proc.terminate()
                    raise OSError("timed out")

            self._emulator_labels[label] = "emulator-%s" % emu_port
        except OSError as e:
            raise CuckooMachineError(
                "Emulator failed starting machine %s: %s" % (label, e)
            )
        except IOError as e:
            raise CuckooMachineError(e)
        finally:
            s.close()
            if emu_conn:
                emu_conn.close()

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
                "-s", self._emulator_labels[label],
                "wait-for-device"
            ]
            p = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            _, err = p.communicate()
            if p.returncode != 0:
                raise OSError(err)
        except OSError as e:
            raise CuckooMachineError(
                "Failed to issue adb command wait-for-device: %s" % e
            )

    def stop(self, label):
        """Stop a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to stop.
        """
        log.debug("Stopping vm %s", label)

        if not label in self._emulator_labels.keys():
            raise CuckooMachineError(
                "Trying to stop a machine that wasn't started: %s" % label
            )

        try:
            args = [
                "sudo", self.options.avd.adb_path,
                "-s", self._emulator_labels[label],
                "emu", "kill"
            ]
            p = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            out, err = p.communicate()

            if p.returncode != 0:
                raise OSError(err)

            # Currently, for the emulator to shut down appropiately, the user
            # needs to ensure that an `.emulator_console_auth_token` exists
            # in their $HOME directory.
            if "KO: unknown command" in out:
                raise OSError(
                    "Unable to authenticate with the emulator console. Make sure "
                    "the authentication token in '$HOME/.emulator_console_"
                    "auth_token' exists."
                )
            del self._emulator_labels[label]
        except OSError as e:
            raise CuckooMachineError(
                "Emulator failed to stop the machine: %s" % e
            )
