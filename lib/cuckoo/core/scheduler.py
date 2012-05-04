import os
import sys
import time
import logging
from threading import Thread

from lib.cuckoo.common.utils import create_folders
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.database import Database
from lib.cuckoo.abstract.machinemanager import MachineManager
from lib.cuckoo.core.guest import GuestManager

log = logging.getLogger(__name__)

MMANAGER = []

class AnalysisManager(Thread):
    def __init__(self, task):
        Thread.__init__(self)
        self.cfg = Config()
        self.db = Database()
        self.task = task

    def init_storage(self):
        self.task.results_folder = os.path.join("storage/analyses/", str(self.task.id))

        if os.path.exists(self.task.results_folder):
            log.error("Analysis results folder already exists at path: %s" % self.task.results_folder)
            return False

        try:
            os.mkdir(self.task.results_folder)
        except OSError as e:
            log.error("Unable to create analysis results \"%s\" folder: %s" % (self.task.results_folder, e))
            return False
        
        return True

    def run(self):
        self.task.file_name = os.path.basename(self.task.file_path)

        if not os.path.exists(self.task.file_path):
            log.error("The file to analyze does not exist at path: %s" % self.task.file_path)
            return False

        if not self.init_storage():
            return False

        while True:
            vm = MMANAGER.acquire(label=self.task.machine, platform=self.task.platform)
            if not vm:
                time.sleep(1)
            else:
                break

        if not self.task.package:
            self.task.package = "exe"

        MMANAGER.start(vm.label)
        guest = GuestManager(vm.ip, vm.platform)
        guest.start_analysis(self.task)
        guest.wait()
        guest.save_results(self.task.results_folder)
        MMANAGER.stop(vm.label)

class Scheduler:
    def __init__(self):
        self.running = True
        self.config = Config()
        self.db = Database()

    def initialize(self):
        global MMANAGER

        name = "plugins.machinemanagers.%s" % self.config.machine_manager
        try:
            __import__(name, globals(), locals(), ["dummy"], -1)
        except ImportError as e:
            sys.exit("Unable to import machine manager plugin: %s" % e)

        MachineManager()
        module = MachineManager.__subclasses__()[0]
        MMANAGER = module()
        MMANAGER.initialize()

        if len(MMANAGER.machines) == 0:
            sys.exit("No machines available")
        else:
            log.info("Loaded %s machine/s" % len(MMANAGER.machines))

    def stop(self):
        self.running = False

    def start(self):
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