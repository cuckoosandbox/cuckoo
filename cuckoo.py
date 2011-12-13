#!/usr/bin/python
# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2011  Claudio "nex" Guarnieri (nex@cuckoobox.org)
# http://www.cuckoobox.org
#
# This file is part of Cuckoo.
#
# Cuckoo is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Cuckoo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.

import os
import sys
import shutil
import logging
import logging.config
import subprocess
import ConfigParser
from Queue import *
from time import time, sleep
from threading import Thread

from cuckoo.config.config import *
from cuckoo.logging.logo import *
from cuckoo.logging.colored import *
from cuckoo.core.db import *
from cuckoo.core.getfiletype import *

log = logging.getLogger("Core")

# Check the virtualization engine from the config fle and tries to retrieve
# and import the corresponding Cuckoo's module.
if CuckooConfig().get_vm_engine().lower() == "virtualbox":
    try:
        from cuckoo.core.virtualbox import *
    except ImportError, why:
        log.critical("Unable to load Cuckoo's VirtualBox module. " \
                     "Please verify your installation.")
        sys.exit(-1)
# If no valid option has been specified, aborts the execution.
else:
    log.critical("No valid virtualization option identified. " \
                 "Please check your configuration file.")
    sys.exit(-1)

# Import the external sniffer module only if required.
if CuckooConfig().use_external_sniffer():
    try:
        from cuckoo.core.sniffer import *
    except ImportError, why:
        log.critical("Unable to import sniffer module. " \
                     "Please verify your installation.")
        sys.exit(-1)

#------------------------------ Global Variables ------------------------------#
# Initialize complete list of virtual machines.
# (Key = virtual machine name, Value = MAC address).
VM_LIST = {}
# Initialize available virtual nachines pool.
VM_POOL = Queue()
#------------------------------------------------------------------------------#

class Analysis(Thread):
    """
    This class handles the whole analysis process.
    """
    def __init__(self, task = None):
        Thread.__init__(self)
        self.vm_id = None
        self.vm_share = None
        self.task = task
        self.sniffer = None
        self.db = None
        self.dst_filename = None
        log = logging.getLogger("Core.Analysis")

    def _clean_share(self, share_path):
        """
        Cleans the specified shared folder.
        @param share_path: a shared folder
        """
        log = logging.getLogger("Core.Analysis.CleanShare")

        total = len(os.listdir(share_path))
        cleaned = 0

        if total == 0:
            log.debug("Nothing to clean in \"%s\"." % share_path)
            return False

        for name in os.listdir(share_path):
            cur_path = os.path.join(share_path, name)

            if not os.path.exists(cur_path):
                continue

            try:
                if os.path.isdir(cur_path):
                    shutil.rmtree(cur_path)
                else:
                    os.remove(cur_path)
                cleaned += 1
            except (IOError, os.error, shutil.Error), why:
                log.error("Unable to remove \"%s\": %s" % (cur_path, why))

        if cleaned == total:
            log.debug("Shared folder \"%s\" cleaned successfully." % share_path)
            return True
        else:
            log.warning("The folder \"%s\" wasn't completely cleaned. " \
                        "Review previour errors." % share_path)
            return False

    def _save_results(self, src, dst):
        """
        Saves analysis results from source to destination path.
        @param src: source path
        @param dst: destination path
        """
        log = logging.getLogger("Core.Analysis.SaveResults")

        if not os.path.exists(src):
            log.error("The folder \"%s\" doesn't exist." % src)
            return False

        if not os.path.exists(dst):
            try:
                os.mkdir(dst)
            except (IOError, os.error), why:
                log.error("Unable to create directory \"%s\": %s" % (dst, why))
                return False
        else:
            log.error("The folder \"%s\" already exists. It should be used " \
                      "for storing results of task with ID %s. " \
                      "Have you deleted Cuckoo's database?"
                      % (dst, self.task["id"]))
            return False

        total = len(os.listdir(src))
        copied = 0

        for name in os.listdir(src):
            cur_path = os.path.join(src, name)
            dst_path = os.path.join(dst, name)

            if not os.path.exists(cur_path):
                continue

            try:
                if os.path.isdir(cur_path):
                    shutil.copytree(cur_path, dst_path)
                else:
                    shutil.copy(cur_path, dst_path)
                copied += 1
            except (IOError, os.error, shutil.Error), why:
                log.error("Unable to copy \"%s\" to \"%s\": %s"
                          % (cur_path, dst_path, why))

        if copied == total:
            log.info("Analysis results successfully saved to \"%s\"." % dst)
            return True
        else:
            log.warning("Results from \"%s\" weren't completely copied to " \
                        "\"%s\". Review previour errors." % (src, dst))
            return False

    def _generate_config(self, share_path):
        """
        Generates the analysis configuration file and saves it to specified
        shared folder.
        @param share_path: path to the destination shared folder
        """
        log = logging.getLogger("Core.Analysis.GenerateConfig")

        if self.task is None:
            return False

        config = ConfigParser.RawConfigParser()

        config.add_section("analysis")
        config.set("analysis", "target", self.dst_filename)
        config.set("analysis", "package", self.task["package"])
        config.set("analysis", "timeout", self.task["timeout"])
        config.set("analysis", "started", time())
        if self.task["custom"]:
            config.set("analysis", "custom", self.task["custom"])
        else:
            config.set("analysis", "custom", "")

        local_share = "\\\\VBOXSVR\\%s\\" % self.vm_id
        config.set("analysis", "share", local_share)

        if os.path.exists(share_path):
            conf_path = os.path.join(share_path, "analysis.conf")
            with open(conf_path, "wb") as config_file:
                config.write(config_file)

            log.debug("Analysis configuration file successfully generated " \
                      "at \"%s\"." % conf_path)

            # Return the local share path. This is the path where the virtual
            # machine will have access to to get analysis files and store
            # results.
            return local_share
        else:
            log.error("Shared folder \"%s\" does not exist." % share_path)
            return False

    def _free_vm(self, vm_id):
        """
        Frees a virtual machine and adds it back to the available pool.
        @param vm_id: identification to the specified virtual machine
        """
        VM_POOL.put(vm_id)
        log = logging.getLogger("Core.Analysis.FreeVM")
        log.info("Virtual machine \"%s\" released." % vm_id)
        return True

    def _processing(self, save_path):
        """
        Invokes post-analysis processing script.
        @param save_path: path to the analysis results folder
        """
        log = logging.getLogger("Core.Analysis.Processing")
        if not os.path.exists(save_path):
            log.error("Cannot find the results folder at path \"%s\"."
                      % save_path)
            return False

        interpreter = CuckooConfig().get_processing_interpreter()

        if not interpreter:
            return False

        if not os.path.exists(interpreter):
            log.error("Cannot find interpreter at path \"%s\"." % interpreter)
            return False

        processor = CuckooConfig().get_processing_processor()

        if not processor:
            return False

        if not os.path.exists(processor):
            log.error("Cannot find processor script at path \"%s\"."
                      % processor)
            return False

        pargs = [interpreter, processor, save_path]

        try:
            pid = subprocess.Popen(pargs).pid
        except Exception, why:
            log.error("Something went wrong while starting processor: %s" % why)
            return False

        log.info("Analysis results processor started with PID \"%d\"." % pid)
        
        return True

    def run(self):
        """
        Handles the analysis process and invokes all required procedures.
        """
        log = logging.getLogger("Core.Analysis.Run")
        success = True

        self.db = CuckooDatabase()

        # Generate analysis results storage folder path with current task id.
        results_path = CuckooConfig().get_analysis_results_path()
        save_path = os.path.join(results_path, str(self.task["id"]))

        # Additional check to verify that the are not saved results with the
        # same task ID.
        if os.path.exists(save_path):
            log.error("There are already stored results for current task " \
                      "with ID %d at path \"%s\". Abort."
                      % (self.task["id"], save_path))
            self.db.complete(self.task["id"], False)
            return False

        # Check if target file exists.
        if not os.path.exists(self.task["target"]):
            log.error("Cannot find target file \"%s\". Abort."
                      % self.task["target"])
            self.db.complete(self.task["id"], False)
            return False

        # Check if target is a directory.
        if os.path.isdir(self.task["target"]):
            log.error("Specified target \"%s\" is a directory. Abort." 
                      % self.task["target"])
            self.db.complete(self.task["id"], False)
            return False

        # Copy original target file name to destination target.
        self.dst_filename = os.path.basename(self.task["target"])

        # 4. If analysis package has not been specified, need to run some
        # perliminary checks on the file.
        if self.task["package"] is None:
            file_type = get_filetype(self.task["target"])
            file_extension = os.path.splitext(self.dst_filename)[1]

            if file_type:
                # Check the file format and see if the file name has the
                # appropriate extension, otherwise fix it. Assign proper
                # default analysis package.
                if file_type.lower() == "exe":
                    if file_extension.lower() != ".exe":
                        self.dst_filename += ".exe"
                        
                    self.task["package"] = "exe"
                elif file_type.lower() == "pdf":
                    if file_extension.lower() != ".pdf":
                        self.dst_filename += ".pdf"

                    self.task["package"] = "pdf"
                else:
                    log.error("Unknown file format for target \"%s\". Abort."
                              % self.task["target"])
                    self.db.complete(self.task["id"], False)
                    return False
            else:
                self.db.complete(self.task["id"], False)
                return False

        # 5. If no analysis timeout is set, get the default from the config
        # file.
        if self.task["timeout"] is None:
            timeout = int(CuckooConfig().get_analysis_analysis_timeout())
            self.task["timeout"] = timeout
        # If the specified timeout is bigger than the watchdog timeout set in
        # the configuration file, I redefine it to the maximum - 30 seconds.
        elif int(self.task["timeout"]) > CuckooConfig().get_analysis_watchdog_timeout():
            self.task["timeout"] = CuckooConfig().get_analysis_watchdog_timeout() - 30
            log.info("Specified analysis timeout is bigger than the watchdog " \
                     "timeout (see cuckoo.conf). Redefined to %s seconds."
                     % self.task["timeout"])

        # 6. Acquire a virtual machine from pool.
        while True:
            self.vm_id = VM_POOL.get()
            if self.vm_id:
                log.info("Acquired virtual machine \"%s\"." % self.vm_id)
                break
            else:
                sleep(1)

        # Get path to current virtual machine's shared folder.
        self.vm_share = CuckooConfig().get_vm_share(self.vm_id)           

        if not os.path.exists(self.vm_share):
            log.error("Shared folder \"%s\" for virtual machine \"%s\" " \
                      "does not exist. Abort.")
            self.db.complete(self.task["id"], False)
            self._free_vm(self.vm_id)
            return False

        # Clean the virtual machine's shared folder in case it was't
        # correctly cleaned previously.
        self._clean_share(self.vm_share)

        # 7. Generate the analysis config file: it will be used by guest
        # components to initialize analysis. If the generation fails,
        # I need to abort execution.
        local_share = self._generate_config(self.vm_share)
        if not local_share:
            self.db.complete(self.task["id"], False)
            self._free_vm(self.vm_id)
            return False

        # 8. Copy target file to the shared folder.
        try:
            dst_path = os.path.join(self.vm_share, self.dst_filename)
            shutil.copy(self.task["target"], dst_path)
        except shutil.Error, why:
            log.error("Cannot copy file \"%s\" to \"%s\": %s"
                      % (self.task["target"], self.vm_share, why))
            self.db.complete(self.task["id"], False)
            self._free_vm(self.vm_id)
            return False

        # 9. Start sniffer.
        # Check if the user has decided to adopt the external sniffer or not.
        # In first case, initialize the sniffer and start it.
        if CuckooConfig().use_external_sniffer():
            pcap_file = os.path.join(self.vm_share, "dump.pcap")
            self.sniffer = Sniffer(pcap_file)
        
            interface = CuckooConfig().get_sniffer_interface().lower()
            guest_mac = VM_LIST[self.vm_id]

            if not self.sniffer.start(interface, guest_mac):
                log.warning("Unable to start sniffer. "  \
                            "Network traffic dump won't be available for " \
                            "current analysis.")
                self.sniffer = None

        vm = VirtualMachine(self.vm_id)

        # 10. I decided to move the virtual machine restore before launching it
        # at first. This is in order both to be sure that it's clean, and also
        # to eventually allow forensic of the machine after the analysis is
        # completed.
        if not vm.restore():
            # If restore failed than I prefere not to put the virtual machine
            # back to the pool as it might be corrupted.
            log.warning("Cannot restore snapshot on virtual machine \"%s\", " \
                        "consequently is not getting re-added to the pool. " \
                        "Review previous errors." % self.vm_id)
            self.db.unlock(self.task["id"])
            return False

        # 11. Start virtual machine
        if not vm.start():
            log.error("Virtual machine start up failed. " \
                      "Analysis is aborted. Review previous errors.")
            # Unlock task id in order to make it run on a different virtual
            # machine. I'm not putting back the currently used one since it's
            # probably broken.
            self.db.unlock(self.task["id"])
            return False

        # Get virtual machines' local Python installation path from config
        # file.
        python_path = CuckooConfig().get_vm_python()
        python_path = python_path.replace("\\", "\\\\")

        args = []
        args.append("\\\\VBOXSVR\\setup\\analyzer.py")
        args.append(local_share)

        # 12. & 13. Launch Cuckoo analyzer component on virtual machine.
        if not vm.execute(python_path, args):
            log.error("Analysis of target file \"%s\" with task ID %d failed." \
                      " Check previous errors."
                      % (self.task["target"], self.task["id"]))
            success = False

        # 14. Stop sniffer.
        if self.sniffer:
            self.sniffer.stop()

        # 15. Save analysis results.
        self._save_results(self.vm_share, save_path)
        # 16. Clean shared folder.
        self._clean_share(self.vm_share)

        # 17. Update task in database with proper status code.
        if success:
            self.db.complete(self.task["id"], True)
        else:
            self.db.complete(self.task["id"], False)

        # 18. Invoke processing script.
        self._processing(save_path)

        # 19. Stop virtual machine.            
        if not vm.stop():
            log.warning("Poweroff of virtual machine \"%s\" failed."
                        % self.vm_id)

        # 20. Add virtual machine back to available pool.
        self._free_vm(self.vm_id)

        log.info("Analyis completed.")

        return True

#                I have malwares for
#          .---.    breakfast!
#         /   6_6       _       .-.
#         \_  (__\     ("\     /.-.\
#         //   \\       `\\   //   \\
#        ((     ))        \`-`/     \'-')
#  =======""===""=========="""======="""===
#           |||
#            |
def main():
    # Analysis Execution Flow:
    # 1.  Connect to database
    # 2.  Acquire task from database
    # 3.  Lock task
    # 4.  Verify analysis package
    # 5.  Verify analysis timeout
    # 6.  Acquire virtual machine
    # 7.  Generate analysis config
    # 8.  Copy target file to shared folder
    # 9. Start sniffer
    # 10. Restore virtual machine snapshot
    # 11. Start virtual machine
    # 12. Start Cuckoo analyzer python script
    # 13. Wait for analysis to finish
    # 14. Stop snfifer
    # 15. Save analysis results
    # 16. Clean shared folder
    # 17. Update task's status in database
    # 18. Invoke processing script.
    # 19. Stop virtual machine
    # 20. Put virtual machine back in the available pool
    running = True
    log = logging.getLogger("Core.Dispatcher")

    # Loop until the end of the world.
    while running:
        # If there are free virtual machines I can start a new analysis.
        if not VM_POOL.empty():
            db = CuckooDatabase()
            task = db.get_task()

            if not task:
                log.debug("No tasks pending.")
                sleep(1)
                continue

            log.info("Acquired analysis task for target \"%s\"."
                     % task["target"])

            # 3. Lock acquired task. If it doesn't get locked successfully I
            # need to abort its execution.
            if not db.lock(task["id"]):
                log.error("Unable to lock task with ID %d." % task["id"])
                sleep(1)
                continue

            analysis = Analysis(task)
            analysis.setName(task["id"])
            analysis.start()
        else:
            log.debug("No free virtual machines.")

        sleep(1)

    return

if __name__ == "__main__":
    logo()

    # Load logging config file.
    logging.config.fileConfig("conf/logging.conf")
    # Hack StreamHandler to color the messages :).
    #logging.StreamHandler.emit = color_stream_emit(logging.StreamHandler.emit)

    # If user enabled debug logging in the configuration file, I modify the
    # root logger level accordingly.
    if CuckooConfig().get_logging_debug():
        root = logging.getLogger()
        root.setLevel(logging.DEBUG)

    log = logging.getLogger("Core.Init")

    log.info("Started.")

    try:
        # Check if something's wrong with the Virtual Machine engine.
        if not VirtualMachine().check():
            sys.exit(-1)

        log.info("Populating virtual machines pool...")

        # Acquire Virtual Machines IDs list from the config file.
        virtual_machines = CuckooConfig().get_vms()
		
        # Start checking informations regarding each enabled virtual machine
        # specified in the config file. Detailed errors and informations are
        # provided during this procedure.
        for vm_id in virtual_machines:
            vm = VirtualMachine(vm_id)

            # If virtual machine check was successful, add it to lists.
            if vm.infos():
                # Check if the current virtual machine's MAC address is alread 
                # present in the list. This is a tricky trick to check if the
                # user cloned the virtual machine and something went wrong with
                # MAC address generation or simply if the user has A.D.D. and
                # repeated the same virtual machine multiple times.
                found = False
                for item in VM_LIST:
                    if vm.mac == item[1]:
                        found = item[0]
			
                if not found:
                    # Add virtual machine to complete list.
                    VM_LIST[vm_id] = vm.mac

                    # Add the current VM to the available pool.
                    VM_POOL.put(vm_id)
                else:
                    log.warning("Virtual machine with name \"%s\" share the " \
                                "the same MAC address \"%s\" with virtual "  \
                                "virtual machine with name \"%s\". " \
                                "Not being added to pool."
                                % (vm.name, vm.mac, found))

        # If virtual machines pool is empty, die.
        if VM_POOL.empty():
            log.critical("None of the virtual machines are available. " \
                         "Please review the errors.")
            sys.exit(-1)
        else:
            log.info("%s virtual machine/s added to pool." % VM_POOL.qsize())

        # If I arrived this far means that the gods of virtualization are in
        # good mood today and nothing screwed up. Cross your fingers and hope
        # it won't while analyzing some 1 billion dollars malware.
        main()
    except KeyboardInterrupt:
        log.critical("Keyboard interrupt catched! " \
                     "Forcing shutdown and restore of all virtual machines " \
                     "before exiting...")

        # When a keyboard interrupt is catched I'm gonna walk through all
        # enabled virtual machines, power them off and then restore their last
        # snapshot.
        for vm_id in VM_LIST:
            vm = VirtualMachine(vm_id)
            vm.stop()
            vm.restore()

        sys.exit()
