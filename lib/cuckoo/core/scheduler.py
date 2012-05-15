import os
import sys
import time
import shutil
import logging
from multiprocessing import Process

from lib.cuckoo.common.exceptions import CuckooAnalysisError, CuckooMachineError
from lib.cuckoo.common.abstracts import Dictionary, MachineManager
from lib.cuckoo.common.utils import File, create_folders
from lib.cuckoo.common.config import Config
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.guest import GuestManager
from lib.cuckoo.core.sniffer import Sniffer
from lib.cuckoo.core.processor import Processor
from lib.cuckoo.core.reporter import Reporter

log = logging.getLogger(__name__)

mmanager = None

class AnalysisManager(Process):
    def __init__(self, task):
        Process.__init__(self)
        Process.daemon = True
        self.task = task
        self.cfg = Config()
        self.db = Database()
        self.analysis = Dictionary()

    def init_storage(self):
        self.analysis.results_folder = os.path.join(os.path.join(os.getcwd(), "storage/analyses/"), str(self.task.id))

        if os.path.exists(self.analysis.results_folder):
            raise CuckooAnalysisError("Analysis results folder already exists at path \"%s\", analysis aborted" % self.analysis.results_folder)

        os.mkdir(self.analysis.results_folder)

    def store_file(self):
        md5 = File(self.task.file_path).get_md5()
        self.analysis.stored_file_path = os.path.join(os.path.join(os.getcwd(), "storage/binaries/"), md5)

        if os.path.exists(self.analysis.stored_file_path):
            log.info("File already exists at \"%s\"" % self.analysis.stored_file_path)
        else:
            try:
                shutil.copy(self.task.file_path, self.analysis.stored_file_path)
            except (IOError, shutil.error) as e:
                raise CuckooAnalysisError("Unable to store file from \"%s\" to \"%s\", analysis aborted"
                                          % (self.task.file_path, self.analysis.stored_file_path))

        try:
            os.symlink(self.analysis.stored_file_path, os.path.join(self.analysis.results_folder, "binary"))
        except OSError as e:
            raise CuckooAnalysisError("Unable to create symlink from \"%s\" to \"%s\"" % (self.analysis.stored_file_path, self.analysis.results_folder))

    def build_options(self):
        options = {}

        if self.task.timeout:
            timeout = self.task.timeout
        else:
            timeout = self.cfg.analysis_timeout

        options["file_path"] = self.task.file_path
        options["file_name"] = File(self.task.file_path).get_name()
        options["file_type"] = File(self.task.file_path).get_type()
        options["package"] = self.task.package
        options["options"] = self.task.options
        options["timeout"] = timeout

        return options

    def launch_analysis(self):
        log.info("Starting analysis of file \"%s\"" % self.task.file_path)

        if not os.path.exists(self.task.file_path):
            raise CuckooAnalysisError("The file to analyze does not exist at path \"%s\", analysis aborted" % self.task.file_path)

        while True:
            vm = mmanager.acquire(label=self.task.machine, platform=self.task.platform)
            if not vm:
                log.debug("No machine available")
                time.sleep(1)
            else:
                log.info("Acquired machine %s" % vm.label)
                break

        self.init_storage()
        self.store_file()
        options = self.build_options()

        # Initialize sniffer
        sniffer = Sniffer(self.cfg.tcpdump)
        sniffer.start(interface=self.cfg.interface, host=vm.ip, file_path=os.path.join(self.analysis.results_folder, "dump.pcap"))
        # Start machine
        mmanager.start(vm.label)
        # Initialize guest manager
        guest = GuestManager(vm.ip, vm.platform)
        # Launch analysis
        guest.start_analysis(options)
        # Wait for analysis to complete
        guest.wait_for_completion()
        # Save results
        guest.save_results(self.analysis.results_folder)
        # Stop machine
        #mmanager.stop(vm.label)
        # Release the machine from lock
        #mmanager.release(vm.label)
        # Stop sniffer
        sniffer.stop()
        # Launch reports generation
        Reporter(self.analysis.results_folder).run(Processor(self.analysis.results_folder).run())

    def run(self):
        success = True

        self.db.lock(self.task.id)

        try:
            self.launch_analysis()
        except CuckooAnalysisError as e:
            log.error(e.message)
            success = False
        finally:
            self.db.complete(self.task.id, success)

class Scheduler:
    def __init__(self):
        self.running = True
        self.config = Config()
        self.db = Database()

    def initialize(self):
        global mmanager

        name = "modules.machinemanagers.%s" % self.config.machine_manager
        try:
            __import__(name, globals(), locals(), ["dummy"], -1)
        except ImportError as e:
            raise CuckooMachineError("Unable to import machine manager plugin: %s" % e)

        MachineManager()
        module = MachineManager.__subclasses__()[0]
        mmanager = module()
        mmanager.initialize(self.config.machine_manager)

        if len(mmanager.machines) == 0:
            raise CuckooMachineError("No machines available")
        else:
            log.info("Loaded %s machine/s" % len(mmanager.machines))

    def stop(self):
        self.running = False

    def start(self):
        self.initialize()

        while self.running:
            time.sleep(1)
            task = self.db.fetch()

            if not task:
                log.debug("No pending tasks, try again")
                continue

            analysis = AnalysisManager(task)
            analysis.daemon = True
            analysis.start()
            analysis.join()

            break