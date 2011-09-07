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
import subprocess
import ConfigParser
from Queue import *
from time import sleep
from threading import Thread

from cuckoo.config import *
from cuckoo.db import *
from cuckoo.getfiletype import *
from cuckoo.logging import *
from cuckoo.logo import *
from cuckoo.sniffer import *
from cuckoo.now import *

# Check the virtualization engine from the config fle and tries to retrieve and
# import the corresponding Cuckoo's module.
if CuckooConfig().get_vm_engine().lower() == "virtualbox":
    try:
        from cuckoo.virtualbox import *
    except ImportError, why:
        log("Unable to load Cuckoo's VirtualBox module." \
            " Please check your installation.\n", "ERROR")
        sys.exit(-1)
# If no valid option has been specified, aborts the execution.
else:
    log("No valid virtualization option identified. " \
        "Please check your configuration file.\n", "ERROR")
    sys.exit(-1)

# Initialize complete list of virtual machines.
# (Key = virtual machine name, Value = mac address).
VM_LIST = {}
# Initialize available virtual nachines pool.
VM_POOL = Queue()

class Analysis(Thread):
    def __init__(self, task = None):
        Thread.__init__(self)
        self.vm_id = None
        self.vm_share = None
        self.task = task
        self.sniffer = None
        self.db = None

    # Clean shared folders.
    def _clean_share(self, share_path):
        total = len(os.listdir(share_path))
        cleaned = 0

        if total == 0:
            log("[Analysis] [Clean Share] Nothing to clean in \"%s\"."
                % share_path, "DEBUG")
            return False

        for name in os.listdir(share_path):
            cur_path = os.path.join(share_path, name)

            if not os.path.exists(cur_path):
                continue

            if os.path.isdir(cur_path):
                try:
                    shutil.rmtree(cur_path)
                    cleaned += 1
                except (IOError, os.error), why:
                    log("[Analysis] [Clean Share] Unable to remove directory " \
                        "\"%s\": %s." % (cur_path, why), "ERROR")
                except shutil.Error, why:
                    log("[Analysis] [Clean Share] Unable to remove directory " \
                        "\"%s\": %s." % (cur_path, why), "ERROR")
            else:
                try:
                    os.remove(cur_path)
                    cleaned += 1
                except (IOError, os.error), why:
                    log("[Analysis] [Clean Share] Unable to remove file \"%s\""\
                        ": %s" % (cur_path, why), "ERROR")

        if cleaned == total:
            log("[Analysis] [Clean Share] Shared folder \"%s\" cleaned " \
                "successfully." % share_path)
            return True
        else:
            log("[Analysis] [Clean Share] The folder \"%s\" wasn't completely" \
                " cleaned. Review previour errors." % share_path, "WARNING")
            return False

    # Save analysis results from source path to destination path.
    def _save_results(self, src, dst):
        if not os.path.exists(src):
            log("[Analysis] [Save Results] The folder \"%s\" doesn't exist.",
                "ERROR")
            return False

        if not os.path.exists(dst):
            try:
                os.mkdir(dst)
            except (IOError, os.error), why:
                log("[Analysis] [Save Results] Unable to create directory " \
                    "\"%s\": %s" % (dst, why), "ERROR")
                return False
        else:
            log("[Analysis] [Save Results] The folder \"%s\" already exists." \
                " It should be used for storing results of task with id %s."  \
                " Have you deleted Cuckoo's database?" % (dst, self.task["id"]),
                "ERROR")
            return False

        total = len(os.listdir(src))
        copied = 0

        for name in os.listdir(src):
            cur_path = os.path.join(src, name)
            dst_path = os.path.join(dst, name)

            if not os.path.exists(cur_path):
                continue

            if os.path.isdir(cur_path):
                try:
                    shutil.copytree(cur_path, dst_path)
                    copied += 1
                except (IOError, os.error), why:
                    log("[Analysis] [Save Results] Unable to copy \"%s\" to " \
                        "\"%s\": %s" % (cur_path, dst_path, why), "ERROR")
                except shutil.Error, why:
                    log("[Analysis] [Save Results] Unable to copy \"%s\" to " \
                        "\"%s\": %s" % (cur_path, dst_path, why), "ERROR")
            else:
                try:
                    shutil.copy(cur_path, dst_path)
                    copied += 1
                except shutil.Error, why:
                    log("[Analysis] [Save Results] Unable to copy \"%s\" to " \
                        "\"%s\": %s" % (cur_path, dst_path, why), "ERROR")

        if copied == total:
            log("[Analysis] [Save Results] Analysis results successfully " \
                "saved to \"%s\"." % dst)
            return True
        else:
            log("[Analysis] [Save Results] Analysis results from \"%s\" " \
                "weren't completely copied to \"%s\". Review previour errors."
                % (src, dst), "ERROR")
            return False

    def _generate_config(self, share_path):
        if self.task is None:
            return False

        config = ConfigParser.RawConfigParser()

        config.add_section("analysis")
        config.set("analysis", "target", os.path.basename(self.task["target"]))
        config.set("analysis", "package", self.task["package"])
        config.set("analysis", "timeout", self.task["timeout"])

        local_share = "\\\\VBOXSVR\\%s\\" % self.vm_id
        config.set("analysis", "share", local_share)

        if os.path.exists(share_path):
            conf_path = os.path.join(share_path, "analysis.conf")
            with open(conf_path, "wb") as config_file:
                config.write(config_file)

            log("[Analysis] [Generate Config] Config file successfully " \
                "generated at \"%s\"." % conf_path)

            # Return the local share path. This is the path where the virtual
            # machine will have access to to get analysis files and store
            # results.
            return local_share
        else:
            log("[Analysis] [Generate Config] Shared folder \"%s\" does not" \
                " exist." % share_path, "ERROR")
            return False

    def _free_vm(self, vm_id):
        VM_POOL.put(vm_id)
        log("[Analysis] [Free VM] Virtual machine \"%s\" released." % vm_id,
            "INFO")
        return True

    def _postprocessing(self, save_path, custom = None):
        if not os.path.exists(save_path):
            log("[Analysis] [Postprocessing] Cannot find the results folder " \
                "at path \"%s\"." % save_path, "ERROR")
            return -1

        processor = CuckooConfig().get_analysis_processor()

        if not processor:
            return -1

        if not os.path.exists(processor):
            log("[Analysis] [Postprocessing] Cannot find processor script at " \
                "path \"%s\"." % processor, "ERROR")
            return -1

        pargs = ['python', processor, save_path]

        # This sends to the postprocessing any eventual custom field specified
        # at submission time in the database.
        if custom:
            pargs.extend([custom])

        try:
            pid = subprocess.Popen(pargs).pid
        except Exception, why:
            log("[Analysis] [Postprocessing] Something went wrong while " \
                "starting processor: %s" % why, "ERROR")
            return -1
        
        return pid

    def run(self):
        success = True
        free_vm = True

        self.db = CuckooDatabase()

        # Generate analysis results storage folder path with current task id.
        results_path = CuckooConfig().get_analysis_results_path()
        save_path = os.path.join(results_path, str(self.task["id"]))

        # Additional check to verify that the are not saved results with the
        # same task ID.
        if os.path.exists(save_path):
            log("[Analysis] [Core] There are already stored results for " \
                "current task with id %s at path \"%s\". Aborting."
                % (self.task["id"], save_path), "ERROR")
            self.db.complete(self.task["id"], False)
            return False

        if not os.path.exists(self.task["target"]):
            log("[Analysis] [Core] Cannot find target file \"%s\". Aborting."
                % self.task["target"], "ERROR")
            self.db.complete(self.task["id"], False)
            return False

        if os.path.isdir(self.task["target"]):
            log("[Analysis] [Core] Specified target \"%s\" is a directory. " \
                "Aborting." % self.task["target"], "ERROR")
            self.db.complete(self.task["id"], False)
            return False

        # 4. If analysis package has not been specified, need to run some
        # perliminary checks on the file.
        if self.task["package"] is None:
            file_extension = os.path.splitext(self.task["target"])[1]
            file_type = get_filetype(self.task["target"])

            if file_type:
                # Check the file format and see if the file name has the
                # appropriate extension, otherwise fix it. Assign proper
                # default analysis package.
                if file_type.lower() == "exe":
                    if file_extension.lower() != ".exe":
                        new_target = self.task["target"] + ".exe"

                        try:
                            os.rename(self.task["target"], new_target)
                        except IOError, why:
                            log("[Analysis] [Core] Cannot rename file from " \
                                "\"%s\" to \"%s\": %s."
                                % (self.task["target"], new_target, why),
                                "ERROR")
                            self.db.complete(self.task["id"], False)
                            return False

                        self.task["target"] = new_target

                    self.task["package"] = "exe"
                elif file_type.lower() == "pdf":
                    if file_extension.lower() != ".pdf":
                        new_target = self.task["target"] + ".pdf"

                        try:
                            os.rename(self.task["target"], new_target)
                        except IOError, why:
                            log("[Analysis] [Core] Cannot rename file from " \
                                "\"%s\" to \"%s\": %s."
                                % (self.task["target"], new_target, why),
                                "ERROR")
                            self.db.complete(self.task["id"], False)
                            return False

                        self.task["target"] = new_target

                    self.task["package"] = "pdf"
                else:
                    log("[Analysis] [Core] Unknown file format for " \
                        "target \"%s\". Aborting."
                        % self.task["target"], "ERROR")
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

        # 6. Acquire a virtual machine from pool.
        while True:
            self.vm_id = VM_POOL.get()
            if self.vm_id:
                break
            else:
                sleep(1)

        # Get path to current virtual machine's shared folder.
        self.vm_share = CuckooConfig().get_vm_share(self.vm_id)           

        if not os.path.exists(self.vm_share):
            log("[Analysis] [Core] Shared folder \"%s\" for virtual " \
                "machine \"%s\" does not exist. Aborting.", "ERROR")
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
            shutil.copy(self.task["target"], self.vm_share)
        except shutil.Error, why:
            log("[Analysis] [Core] Cannot copy file \"%s\" to shared" \
                " folder \"%s\": %s"
                % (self.task["target"], self.vm_share, why), "ERROR")
            self.db.complete(self.task["id"], False)
            self._free_vm(self.vm_id)
            return False

        # 9a. Initialize the network sniffer.
        pcap_path = os.path.join(self.vm_share, "pcap/")
        if not os.path.exists(pcap_path):
            try:
                os.mkdir(pcap_path)
                pcap_file = os.path.join(pcap_path, "dump.pcap")
                self.sniffer = Sniffer(pcap_file)
            except (IOError, os.error), why:
                log("[Analysis] [Core] Cannot create pcap folder at " \
                    "path \"%s\": %s. Network traffic dump won't be " \
                    "available for current analysis."
                    % (pcap_path, why), "WARNING")

        # 9b. Start sniffer.
        if self.sniffer:
            interface = CuckooConfig().get_host_interface()
            guest_mac = VM_LIST[self.vm_id]

            if not self.sniffer.start(interface, guest_mac):
                log("[Analysis] [Core] Unable to start sniffer. "  \
                    "Network traffic dump won't be available for " \
                    "current analysis.", "WARNING")
                self.sniffer = None

        vm = VirtualMachine(self.vm_id)
        # 10. Start virtual machine
        if not vm.start():
            log("[Analysis] [Core] Virtual machine start up failed. Analysis " \
                "is aborted. Review previous errors.", "ERROR")
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
        args.append("\\\\VBOXSVR\\setup\\cuckoovm.py")
        args.append(local_share)

        # 11. & 12. Launch Cuckoo's python run component.
        if not vm.execute(python_path, args):
            log("[Analysis] [Core] Analysis of target file \"%s\" with " \
                "task id %s failed. Check previous errors."
                % (self.task["target"], self.task["id"]), "ERROR")
            success = False

        # 13. Stop virtual machine.
        if vm.stop():
            # TODO: this is a quick hacky fix for the error that VirtualBox
            # sometimes encounters while trying to lock a session after a
            # poweroff. Need to found a better solution.
            sleep(5)
            # 14. Restore virtual machine snapshot.
            vm.restore()
        else:
            # If shutdown failed than I prefere not to put the virtual machine
            # back to the pool as it might be corrupted.
            log("[Analysis] [Core] Poweroff of virtual machine \"%s\" and "  \
                "consequently is not getting re-added to pool. Review "      \
                "previous errors." % self.vm_id, "ERROR")
            free_vm = False

        # 15. Stop sniffer.
        if self.sniffer:
            self.sniffer.stop()

        # 16. Save analysis results.
        self._save_results(self.vm_share, save_path)
        # 17. Clean shared folder.
        self._clean_share(self.vm_share)

        # 18. Update task in database with proper status code.
        if success:
            self.db.complete(self.task["id"], True)
        else:
            self.db.complete(self.task["id"], False)

        # 19. Put virtual machine back to the pool.
        if free_vm:
            self._free_vm(self.vm_id)

        # 20. Invoke postprocessing script.
        processor_pid = self._postprocessing(save_path, self.task["custom"])
        if processor_pid > -1:
            log("[Analysis] [Core] Postprocessing script started with pid " \
                "\"%d\"." % processor_pid, "INFO")

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
    # 9.  Start sniffer
    # 10. Start virtual machine
    # 11. Start Cuckoo's python run script
    # 12. Wait for analysis to finish
    # 13. Stop virtual machine
    # 14. Restore virtual machine snapshot
    # 15. Stop snfifer
    # 16. Save analysis results
    # 17. Clean shared folder
    # 18. Update task's status in database
    # 19. Put virtual machine back in the available pool
    # 20. Invoke postprocessing script.
    running = True

    # Loop until the end of the world.
    while running:
        # If there actually are free virtual machines, than I can start a new
        # analysis procedure.
        if not VM_POOL.empty():
            db = CuckooDatabase()
            task = db.get_task()

            if not task:
                log("[Core] [Dispatcher] No task pending.", "DEBUG")
                sleep(1)
                continue

            log("[Core] [Dispatcher] Acquired analysis task for target \"%s\"."
                % task["target"])

            # 3. Lock acquired task. If it doesn't get locked successfully I need
            # to abort its execution.
            if not db.lock(task["id"]):
                log("[Core] [Dispatcher] Unable to lock task with id %s."
                    % task["id"], "ERROR")
                sleep(1)
                continue

            analysis = Analysis(task).start()
        else:
            log("[Core] [Dispatcher] No free virtual machines.", "DEBUG")
        
        # Anti-Flood Enterprise Protection System.
        sleep(1)

    return

if __name__ == "__main__":
    try:
        logo()
        
        # Check if something's wrong with the Virtual Machine engine.
        if not VirtualMachine().check():
            sys.exit(-1)

        log("[Start Up] Populating virtual machines pool...")

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
                    log("[Start Up] Virtual machine with name \"%s\" share " \
                        "the same MAC address \"%s\" with virtual machine "  \
                        "with name \"%s\". Not being added to pool."
                        % (vm.name, vm.mac, found))

        # If virtual machines pool is empty, die.
        if VM_POOL.empty():
            log("[Start Up] None of the specified virtual machines " \
                "are available. Please review the errors.", "ERROR")
            sys.exit(-1)
        else:
            log("[Start Up] %s virtual machine/s added to pool."
                % VM_POOL.qsize(), "INFO")

        # If I arrived this far means that the gods of virtualization are in
        # good mood today and nothing screwed up. Cross your fingers and hope
        # it won't while analyzing some 1 billion dollars malware.
        main()
    except KeyboardInterrupt:
        log("[Core] Keyboard Interrupt. Exiting...")
        sys.exit()
