# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import logging
import os
import subprocess
import time
import shutil
import shlex

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.core.resultserver import ResultServer

log = logging.getLogger(__name__)

class Avd(Machinery):
    """Virtualization layer for Android Emulator."""

    def _initialize_check(self):
        """Runs all checks when a machine manager is initialized.
        @raise CuckooMachineError: if the android emulator is not found.
        """
        self.emulator_processes = {}

        if not self.options.avd.emulator_path:
            raise CuckooCriticalError("emulator path missing, "
                                      "please add it to the config file")

        if not os.path.exists(self.options.avd.emulator_path):
            raise CuckooCriticalError("emulator not found at "
                                      "specified path \"%s\"" %
                                      self.options.avd.emulator_path)

        if not self.options.avd.adb_path:
            raise CuckooCriticalError("adb path missing, "
                                      "please add it to the config file")

        if not os.path.exists(self.options.avd.adb_path):
            raise CuckooCriticalError("adb not found at "
                                      "specified path \"%s\"" %
                                      self.options.avd.adb_path)

        if not self.options.avd.avd_path:
            raise CuckooCriticalError("avd path missing, "
                                      "please add it to the config file")

        if not os.path.exists(self.options.avd.avd_path):
            raise CuckooCriticalError("avd not found at "
                                      "specified path \"%s\"" %
                                      self.options.avd.avd_path)

        if not self.options.avd.reference_machine:
            raise CuckooCriticalError("reference machine path missing, "
                                      "please add it to the config file")

        machine_path = os.path.join(self.options.avd.avd_path,
                                    self.options.avd.reference_machine)
        if not os.path.exists("%s.avd" % machine_path) or \
                not os.path.exists("%s.ini" % machine_path):
            raise CuckooCriticalError("reference machine not found at "
                                      "specified path \"%s\"" % machine_path)

    def start(self, label, task):
        """Start a virtual machine.
        @param label: virtual machine name.
        @param task: task object.
        @raise CuckooMachineError: if unable to start.
        """
        log.debug("Starting vm %s" % label)

        self.duplicate_reference_machine(label)
        self.start_emulator(label, task)
        self.port_forward(label)
        self.start_agent(label)
        # If mitmdump is active, install its certificate
        mitmdump_certificate = task.options.get('mitmdump_certificate')
        if mitmdump_certificate:
            self.install_certificate(label, task, mitmdump_certificate)

    def stop(self, label):
        """Stops a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to stop.
        """
        log.debug("Stopping vm %s" % label)
        self.stop_emulator(label)

    def _list(self):
        """Lists virtual machines installed.
        @return: virtual machine names list.
        """
        return self.options.avd.machines

    def _status(self, label):
        """Gets current status of a vm.
        @param label: virtual machine name.
        @return: status string.
        """
        log.debug("Getting status for %s" % label)

    def duplicate_reference_machine(self, label):
        """Creates a new emulator based on a reference one."""
        reference_machine = self.options.avd.reference_machine
        log.debug("Duplicate Reference Machine '{0}'.".format(reference_machine))

        # Clean/delete if new emulator already exists.
        self.delete_old_emulator(label)

        avd_config_file = os.path.join(self.options.avd.avd_path, reference_machine+".ini")
        new_config_file = os.path.join(self.options.avd.avd_path, label+".ini")
        reference_avd_path = os.path.join(self.options.avd.avd_path, reference_machine+".avd/")
        new_avd_path = os.path.join(self.options.avd.avd_path, label+".avd/")
        hw_qemu_config_file = os.path.join(new_avd_path, "hardware-qemu.ini")

        # First we copy the template.
        log.debug("Copy AVD reference config file '{0}' in '{1}'...".format(avd_config_file, new_config_file))
        shutil.copyfile(avd_config_file, new_config_file)

        # Copy the internal files of the reference avd.
        log.debug("Duplicate the AVD internal content from '{0}' in '{1}'...".format(reference_avd_path, new_avd_path))
        cmd = "cp -R {0} {1}".format(reference_avd_path, new_avd_path)
        OSCommand.executeCommand(cmd)

        # Than adapt the content of the copied files.
        self.replace_content_in_file(new_config_file, reference_machine, label)
        self.replace_content_in_file(hw_qemu_config_file, reference_machine, label)

        # self.state = AVDEmulator.STATE_PREPARED
        # todo:will see

    def delete_old_emulator(self, label):
        """Deletes any trace of an emulator that would have the same name as
        the one of the current emulator."""
        old_emulator_config_file = os.path.join(self.options.avd.avd_path,
                                                "%s.ini" % label)

        if os.path.exists(old_emulator_config_file):
            log.debug("Deleting old emulator config file '{0}'".format(old_emulator_config_file))
            os.remove(old_emulator_config_file)

        old_emulator_path = os.path.join(self.options.avd.avd_path, label+".avd/")
        if os.path.isdir(old_emulator_path):
            log.debug("Deleting old emulator FS '{0}'".format(old_emulator_path))
            shutil.rmtree(old_emulator_path)

    def replace_content_in_file(self, fileName, contentToReplace, replacementContent):
        """Replaces the specified motif by a specified value in the specified
        file.
        """

        log.debug("Replacing '{0}' with '{1}' in '{2}'".format(contentToReplace, replacementContent, fileName))
        newLines = []
        with open(fileName, 'r') as fd:
            lines = fd.readlines()
            for line in lines:
                newLines.append(line.replace(contentToReplace, replacementContent))

        with open(fileName, 'w') as fd:
            fd.writelines(newLines)

    def start_emulator(self, label, task):
        """Starts the emulator."""
        emulator_port = self.options.get(label)["emulator_port"]

        cmd = [
            self.options.avd.emulator_path,
            "@%s" % label,
            "-no-snapshot-save",
            "-netspeed",
            "full",
            "-netdelay",
            "none",
            "-port",
            "%s" % emulator_port,
            "-tcpdump",
            self.pcap_path(task.id),
        ]

        # In headless mode we remove the skin, audio, and window support.
        if self.options.avd.mode == "headless":
            cmd += ["-no-skin", "-no-audio", "-no-window"]

        # If a proxy address has been provided for this analysis, then we have
        # to pass the proxy address along to the emulator command. The
        # mitmproxy instance is not located at the resultserver's IP address
        # though, so we manually replace the IP address by localhost.
        if "proxy" in task.options:
            _, port = task.options["proxy"].split(":")
            cmd += ["-http-proxy", "http://127.0.0.1:%s" % port]

        self.emulator_processes[label] = OSCommand.executeAsyncCommand(cmd)
        time.sleep(10)
        # if not self.__checkADBRecognizeEmu(label):
        self.restart_adb_server()
        # Waits for device to be ready.
        self.wait_for_device_ready(label)

    def stop_emulator(self, label):
        """Stop the emulator."""
        emulator_port = str(self.options.get(label)["emulator_port"])
        log.info("Stopping AVD listening on port {0}".format(emulator_port))

        # Kill process.
        cmd = [
            self.options.avd.adb_path,
            "-s", "emulator-%s" % emulator_port,
            "emu", "kill",
        ]
        OSCommand.executeCommand(cmd)

        time.sleep(1)
        if label in self.emulator_processes:
            try:
                self.emulator_processes[label].kill()
            except Exception as e:
                log.warning(e)

            del self.emulator_processes[label]

    def wait_for_device_ready(self, label):
        """Analyzes the emulator and returns when it's ready."""

        emulator_port = str(self.options.get(label)["emulator_port"])
        adb = self.options.avd.adb_path

        log.debug("Waiting for device emulator-"+emulator_port+" to be ready.")
        cmd = [
            adb,
            "-s", "emulator-%s" % emulator_port,
            "wait-for-device",
        ]
        OSCommand.executeCommand(cmd)

        log.debug("Waiting for the emulator to be ready")
        log.debug(" - (dev.bootcomplete)")
        ready = False
        while not ready:
            cmd = [
                adb,
                "-s", "emulator-%s" % emulator_port,
                "shell", "getprop", "dev.bootcomplete",
            ]
            result = OSCommand.executeCommand(cmd)
            if result is not None and result.strip() == "1":
                ready = True
            else:
                time.sleep(1)

        log.debug("- (sys_bootcomplete)")
        ready = False
        while not ready:
            cmd = [
                adb,
                "-s", "emulator-%s" % emulator_port,
                "shell", "getprop", "sys.boot_completed",
            ]
            result = OSCommand.executeCommand(cmd)
            if result is not None and result.strip() == "1":
                ready = True
            else:
                time.sleep(1)

        log.debug(" - (init.svc.bootanim)")
        ready = False
        while not ready:
            cmd = [
                adb,
                "-s", "emulator-%s" % emulator_port,
                "shell", "getprop", "init.svc.bootanim",
            ]
            result = OSCommand.executeCommand(cmd)
            if result is not None and result.strip() == "stopped":
                ready = True
            else:
                time.sleep(1)

        time.sleep(5)
        log.debug("Emulator emulator-"+emulator_port+" is ready !")

    def port_forward(self, label):
        cmd = [
            self.options.avd.adb_path,
            "-s", "emulator-%s" % self.options.get(label)["emulator_port"],
            "forward", "tcp:8000", "tcp:8000",
        ]
        OSCommand.executeAsyncCommand(cmd)

    def start_agent(self, label):
        cmd = [
            self.options.avd.adb_path,
            "-s", "emulator-%s" % self.options.get(label)["emulator_port"],
            "shell", "/data/local/agent.sh",
        ]
        OSCommand.executeAsyncCommand(cmd)
        # Sleep 10 seconds to allow the agent to startup properly
        time.sleep(10)

    def install_certificate(self, label, task, mitmdump_certificate):
        """ Copy the CA certificate for mitmdump to the AVD """
        # Determine the hash of the certificate
        file_name = OSCommand.executeCommand(
            'openssl x509 -inform PEM -subject_hash_old'
            ' -in %s' % mitmdump_certificate).split('\n', 1)[0]
        # Write the certificate in the format that Android uses
        cert_file_name = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                               "%d" % task.id, '%s.0' % file_name)
        with open(cert_file_name, 'wb') as cert_file:
            with open(mitmdump_certificate, 'rb') as c:
                cert_file.write(c.read())
            fingerprint = OSCommand.executeCommand('openssl x509 -in %s'
                ' -text -fingerprint -noout' % mitmdump_certificate)
            cert_file.write(fingerprint)
        # Remount /system as writable and push the certifcate to the AVD
        cmd = [
            self.options.avd.adb_path,
            'shell', 'mount', '-o', 'remount,rw', '/system',
        ]
        OSCommand.executeCommand(cmd)
        cmd = [
            self.options.avd.adb_path,
            'push', cert_file_name, '/system/etc/security/cacerts/'
        ]
        # Set permissions and make /system readonly again
        OSCommand.executeCommand(cmd)
        cmd = [
            self.options.avd.adb_path,
            'shell', 'chmod', '644',
            '/system/etc/security/cacerts/%s' % cert_file_name
        ]
        OSCommand.executeCommand(cmd)
        cmd = [
            self.options.avd.adb_path,
            'shell', 'mount', '-o', 'remount,ro', '/system',
        ]
        OSCommand.executeCommand(cmd)
        # Delete the certifcate from the buffer
        os.remove(cert_file_name)

    def check_adb_recognize_emulator(self, label):
        """Checks that ADB recognizes the emulator. Returns True if device is
        recognized by ADB, False otherwise.
        """
        log.debug("Checking if ADB recognizes emulator...")

        cmd = [self.options.avd.adb_path, "devices"]
        output = OSCommand.executeCommand(cmd)

        emu = "emulator-%s" % self.options.get(label)["emulator_port"]
        if emu in output:
            log.debug("Emulator has been found!")
            return True

        log.debug("Emulator has not been found.")
        return False

    def restart_adb_server(self):
        """Restarts ADB server. This function is not used because we have to
        verify we don't have multiple devices.
        """
        log.debug("Restarting ADB server...")

        cmd = [self.options.avd.adb_path, "kill-server"]
        OSCommand.executeCommand(cmd)
        log.debug("ADB server has been killed.")

        cmd = [self.options.avd.adb_path, "start-server"]
        OSCommand.executeCommand(cmd)
        log.debug("ADB server has been restarted.")

    def get_task_id(self, label):
        analysistasks = ResultServer().analysistasks
        for task_ip in analysistasks:
            if analysistasks[task_ip][1].label is label:
                return analysistasks[task_ip][0].id

        return None

class OSCommand(object):
    """Tool class that provides common methods to execute commands on the OS."""

    @staticmethod
    def executeAsyncCommand(commandAndArgs):
        return subprocess.Popen(commandAndArgs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    @staticmethod
    def executeCommand(commandAndArgs):
        if isinstance(commandAndArgs, str):
            commandAndArgs = shlex.split(commandAndArgs)

        try:
            return subprocess.check_output(commandAndArgs, stderr=subprocess.STDOUT)
        except Exception:
            return None
