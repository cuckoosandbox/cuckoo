import os
import sys
import time
from threading import Thread

from lib.cuckoo.common.utils import create_folders
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.database import Database
from lib.cuckoo.abstract.machinemanager import MachineManager
from lib.cuckoo.core.guest import GuestManager

MMANAGER = []

class AnalysisManager(Thread):
    def __init__(self, task):
        Thread.__init__(self)
        self.cfg = Config()
        self.db = Database()
        self.task = task

    def run(self):
        if not os.path.exists(self.task.file_path):
            return False

        results_folder = os.path.join("storage/analyses/", str(self.task.id))

        if os.path.exists(results_folder):
            return False

        try:
            os.mkdir(results_folder)
        except OSError:
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
        guest.get_results(results_folder)
        MMANAGER.stop(vm.label)
        print "Finished!"

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
            sys.exit("Unable to import machime manager plugin: %s" % e)

        MachineManager()
        module = MachineManager.__subclasses__()[0]
        MMANAGER = module()
        MMANAGER.initialize()

        if len(MMANAGER.machines) == 0:
            sys.exit("No machines")
        else:
            print "Loaded %s machine/s" % len(MMANAGER.machines)

    def stop(self):
        self.running = False

    def start(self):
        self.initialize()

        while self.running:
            time.sleep(1)
            task = self.db.fetch()

            if not task:
                continue

            analysis = AnalysisManager(task)
            analysis.daemon = True
            analysis.start()
            analysis.join()
            break