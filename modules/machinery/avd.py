# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.


import logging
import os
import subprocess
import re
import time
import shutil
import shlex
from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.exceptions import CuckooCriticalError, CuckooMachineError
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.resultserver import ResultServer

log = logging.getLogger(__name__)

class Avd(Machinery):
    """Virtualization layer for Android Emulator."""

    def _initialize_check(self):
        """Runs all checks when a machine manager is initialized.
        @raise CuckooMachineError: if VBoxManage is not found.
        """
        #todo:remove
        #self.options = Config(os.path.join(CUCKOO_ROOT, "conf", "avd_new.conf"))

        #todo check!!!
        self.emulator_processes={}

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
        machine_path=os.path.join(self.options.avd.avd_path,self.options.avd.reference_machine)
        if not (os.path.exists(machine_path+".avd") and os.path.exists(machine_path+".ini") ):
            raise CuckooCriticalError("reference machine not found at "
                                      "specified path \"%s\"" %
                                      machine_path)


    def start(self, label):
        """Start a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to start.
        """
        log.debug("Starting vm %s" % label)

        self.duplicate_reference_machine(label)
        self.start_emulator(label)
        self.port_forward(label)
        self.start_agent(label)
        

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
        #todo:fixxxxxx

    def duplicate_reference_machine(self,label):
            """Creates a new emulator based on a reference one."""
            reference_machine=self.options.avd.reference_machine
            log.debug("Duplicate Reference Machine '{0}'.".format(reference_machine))
    
            # clean/delete if new emulator already exists
            self.delete_old_emulator(label)

            avd_config_file = os.path.join(self.options.avd.avd_path, reference_machine+".ini")
            new_config_file = os.path.join(self.options.avd.avd_path, label+".ini")
            reference_avd_path = os.path.join(self.options.avd.avd_path, reference_machine+".avd/")
            new_avd_path = os.path.join(self.options.avd.avd_path, label+".avd/")
            hw_qemu_config_file = os.path.join(new_avd_path, "hardware-qemu.ini")
    
            # First we copy the template       
            log.debug("Copy AVD reference config file '{0}' in '{1}'...".format(avd_config_file, new_config_file))
            shutil.copyfile(avd_config_file, new_config_file)
    
            # Copy the internal files of the reference avd
            log.debug("Duplicate the AVD internal content from '{0}' in '{1}'...".format(reference_avd_path, new_avd_path))
            cmd = "cp -R {0} {1}".format(reference_avd_path, new_avd_path)
            OSCommand.executeCommand(cmd)
    
            # Than adapt the content of the copied files
            self.replace_content_in_file(new_config_file, reference_machine, label)
            self.replace_content_in_file(hw_qemu_config_file, reference_machine, label)
    
            #self.state = AVDEmulator.STATE_PREPARED
            #todo:will see
    
    def delete_old_emulator(self,label):
            """Deletes any trace of an emulator that would have the same name as the one of the current emulator."""
            
            old_emulator_config_file = os.path.join(self.options.avd.avd_path, label+".ini")
                               
            if os.path.exists(old_emulator_config_file):
                log.debug("Deleting old emulator config file '{0}'".format(old_emulator_config_file))
                os.remove(old_emulator_config_file)
    
            old_emulator_path = os.path.join(self.options.avd.avd_path, label+".avd/")
            if os.path.isdir(old_emulator_path):
                log.debug("Deleting old emulator FS '{0}'".format(old_emulator_path))
                shutil.rmtree(old_emulator_path)

    def replace_content_in_file(self, fileName, contentToReplace, replacementContent):
        """Replaces the specified motif by a specified value in the specified file"""

        log.debug("Replacing '{0}' with '{1}' in '{2}'".format(contentToReplace, replacementContent, fileName))
        newLines = []
        with open(fileName, 'r') as fd:
            lines = fd.readlines()
            for line in lines:
                newLines.append(line.replace(contentToReplace, replacementContent))

        with open(fileName, 'w') as fd:
            fd.writelines(newLines)

    def start_emulator(self,label):
        emulator_port = str(self.options.get(label)["emulator_port"])
        
        task_id = self.get_task_id(label)
        if task_id is None:
            raise CuckooCriticalError("android emulator failed starting the machine ,can't find task_id")

        """Starts the emulator"""
        pcap_dump_path=os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "dump.pcap")
        cmd = [
            self.options.avd.emulator_path,
            "@{0}".format(label),
            "-no-snapshot-save",
            "-netspeed",
            "full",
            "-netdelay",
            "none",
            "-port",
            emulator_port,
            "-tcpdump",
            pcap_dump_path
        ]

        self.emulator_processes[label] = OSCommand.executeAsyncCommand(cmd)
        time.sleep(10)
        #if not self.__checkADBRecognizeEmu(label):
        self.restart_adb_server()
        # waits for device to be ready
        self.wait_for_device_ready(label)

    def stop_emulator(self,label):
        """ Stop the emulator"""
        emulator_port=str(self.options.get(label)["emulator_port"])
        log.info("Stopping AVD listening on port {0}".format(emulator_port))

        #Kill process
        cmd = [self.options.avd.adb_path,"-s","emulator-"+emulator_port,"emu","kill"]
        OSCommand.executeCommand(cmd)

        time.sleep(1)
        if label in self.emulator_processes:
            try:
                self.emulator_processes[label].kill()
            except Exception as e:
                log.warning(e)

            del self.emulator_processes[label]

    def wait_for_device_ready(self,label):
        """Analyzes the emulator and returns when it's ready."""

        emulator_port=str(self.options.get(label)["emulator_port"])
        adb=self.options.avd.adb_path

        log.debug("Waiting for device emulator-"+emulator_port+" to be ready.")
        cmd = [adb,"-s","emulator-"+emulator_port,"wait-for-device"]
        OSCommand.executeCommand(cmd)

        log.debug("Waiting for the emulator to be ready")
        log.debug(" - (dev.bootcomplete)")
        ready = False
        while not ready:
            cmd = [adb,"-s","emulator-"+emulator_port,"shell","getprop","dev.bootcomplete"]
            result = OSCommand.executeCommand(cmd)
            if result is not None and result.strip() == "1":
                ready = True
            else:
                time.sleep(1)

        log.debug("- (sys_bootcomplete)")
        ready = False
        while not ready:
            cmd = [adb,"-s","emulator-"+emulator_port,"shell","getprop","sys.boot_completed"]
            result = OSCommand.executeCommand(cmd)
            if result is not None and result.strip() == "1":
                ready = True
            else:
                time.sleep(1)

        log.debug(" - (init.svc.bootanim)")
        ready = False
        while not ready:
            cmd = [adb,"-s","emulator-"+emulator_port,"shell","getprop","init.svc.bootanim"]
            result = OSCommand.executeCommand(cmd)
            if result is not None and result.strip() == "stopped":
                ready = True
            else:
                time.sleep(1)

        time.sleep(5)
        log.debug("Emulator emulator-"+emulator_port+" is ready !")

    def port_forward(self,label):
        cmd = [self.options.avd.adb_path,"-s","emulator-"+str(self.options.get(label)["emulator_port"]),"forward","tcp:8000","tcp:8000"]
        OSCommand.executeAsyncCommand(cmd)

    def start_agent(self,label):
        cmd = [self.options.avd.adb_path,"-s","emulator-"+str(self.options.get(label)["emulator_port"]),"shell","/data/local/agent.sh"]
        OSCommand.executeAsyncCommand(cmd)

    def check_adb_recognize_emulator(self,label):
        """
        Checks that ADB recognizes the emulator. Returns True if device is recognized by ADB, False otherwise.
        """
        log.debug("Checking if ADB recognizes emulator...")

        cmd = [self.options.avd.adb_path,"devices"]

        output = OSCommand.executeCommand(cmd)

        if "emulator-"+str(self.options.get(label)["emulator_port"]) in output:
            log.debug("Emulator has been find!")
            return True

        log.debug("Emulator has not been found.")
        return False

    def restart_adb_server(self):
        """
        Restarts ADB server. This function is not used because we have to verify we don't have multiple devices.
        """
        log.debug("Restarting ADB server...")

        cmd = [self.options.avd.adb_path,"kill-server"]
        OSCommand.executeCommand(cmd)
        log.debug("ADB server has been killed.")

        cmd = [self.options.avd.adb_path,"start-server"]
        OSCommand.executeCommand(cmd)
        log.debug("ADB server has been restarted.")

    def get_task_id(self,label):
        analysistasks= ResultServer().analysistasks
        for task_ip in analysistasks:
            if analysistasks[task_ip][1].label is label:
                return analysistasks[task_ip][0].id

        return None

class OSCommand(object):
    """Tool class that provides common methods to execute commands on the OS
    """

    @staticmethod
    def executeAsyncCommand(commandAndArgs):
        #logger = Logger.getLogger(__name__)
        #logger.debug("Executing Asynchronous command {0}".format(commandAndArgs))

        return subprocess.Popen(commandAndArgs ,stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    @staticmethod
    def executeCommand(commandAndArgs):
        #logger = Logger.getLogger(__name__)

        if isinstance(commandAndArgs, str):
            commandAndArgs = shlex.split(commandAndArgs)

        #logger.debug("Executing command {0}".format(commandAndArgs))
        try:
            return subprocess.check_output(commandAndArgs, stderr=subprocess.STDOUT)
        except Exception, e:
            #logger.error("Error occured while executing command : {0}".format(e))
            return None
