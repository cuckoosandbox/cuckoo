import os
import sys
import time
import shutil
import logging
from multiprocessing import Process

from lib.cuckoo.common.exceptions import CuckooMachineError
from lib.cuckoo.common.abstracts import Dictionary, MachineManager
from lib.cuckoo.common.utils import File, create_folders
from lib.cuckoo.common.config import Config
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.guest import GuestManager
from lib.cuckoo.core.packages import choose_package
from lib.cuckoo.core.processor import Processor
from lib.cuckoo.core.reporter import Reporter

log = logging.getLogger(__name__)

MMANAGER = None

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
            log.error("Analysis results folder already exists at path \"%s\", analysis aborted" % self.analysis.results_folder)
            return False

        os.mkdir(self.analysis.results_folder)

        return True

    def store_file(self):
        md5 = File(self.task.file_path).get_md5()
        self.analysis.stored_file_path = os.path.join(os.path.join(os.getcwd(), "storage/binaries/"), md5)

        if os.path.exists(self.analysis.stored_file_path):
            log.info("File already exists at \"%s\"" % self.analysis.stored_file_path)
        else:
            shutil.copy(self.task.file_path, self.analysis.stored_file_path)

        os.symlink(self.analysis.stored_file_path, os.path.join(self.analysis.results_folder, "binary"))

        return True

    def build_options(self):
        options = {}
        self.analysis.file_type = File(self.task.file_path).get_type()
        
        if not self.task.package:
            package = choose_package(self.analysis.file_type)
            if not package:
                log.error("No default package supports the file format \"%s\", analysis aborted" % self.analysis.file_type)
                return False
        else:
            package = self.task.package

        if self.task.timeout:
            timeout = self.task.timeout
        else:
            timeout = self.cfg.analysis_timeout

        options["file_path"] = self.task.file_path
        options["file_name"] = File(self.task.file_path).get_name()
        options["package"] = package
        options["timeout"] = timeout

        return options

    def run(self):
        #self.db.lock(self.task.id)

        if not os.path.exists(self.task.file_path):
            log.error("The file to analyze does not exist at path \"%s\", analysis aborted" % self.task.file_path)
            return False

        if not self.init_storage():
            return False

        self.store_file()

        options = self.build_options()
        if not options:
            return False

        log.debug("Acquiring virtual machine")

        while True:
            vm = MMANAGER.acquire(label=self.task.machine, platform=self.task.platform)
            if not vm:
                log.debug("No machine available")
                time.sleep(1)
            else:
                log.info("Acquired machine %s" % vm.label)
                break

        MMANAGER.start(vm.label)
        guest = GuestManager(vm.ip, vm.platform)
        guest.start_analysis(options)
        guest.wait_for_completion()
        guest.save_results(self.analysis.results_folder)
        MMANAGER.stop(vm.label)

        Reporter(self.analysis.results_folder).run(Processor(self.analysis.results_folder).run())

class Scheduler:
    def __init__(self):
        self.running = True
        self.config = Config()
        self.db = Database()

    def initialize(self):
        global MMANAGER

        name = "modules.machinemanagers.%s" % self.config.machine_manager
        try:
            __import__(name, globals(), locals(), ["dummy"], -1)
        except ImportError as e:
            raise CuckooMachineError("Unable to import machine manager plugin: %s" % e)

        MachineManager()
        module = MachineManager.__subclasses__()[0]
        MMANAGER = module()
        MMANAGER.initialize()

        if len(MMANAGER.machines) == 0:
            raise CuckooMachineError("No machines available")
        else:
            log.info("Loaded %s machine/s" % len(MMANAGER.machines))

    def stop(self):
        log.info("STOP")
        self.running = False

    def start(self):
        log.info("START")

        self.initialize()

        while self.running:
            time.sleep(1)
            task = self.db.fetch()

            if not task:
                log.debug("No pending tasks")
                continue

            analysis = AnalysisManager(task)
            analysis.daemon = True
            analysis.start()
            analysis.join()
            break