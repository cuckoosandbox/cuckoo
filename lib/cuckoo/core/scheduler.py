import sys
import time
from threading import Thread

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.database import Database
from lib.cuckoo.abstract.machinemanager import MachineManager
from lib.cuckoo.abstract.guestmanager import GuestManager

MACHINES = []

class AnalysisManager(Thread):
    def __init__(self, task):
        Thread.__init__(self)
        self.cfg = Config()
        self.db = Database()
        self.task = task

    def run(self):
        print MACHINES
        print self.task

class Scheduler:
    def __init__(self):
        self.running = True
        self.config  = Config()
        self.db      = Database()

    def initialize(self):
        global MACHINES

        name = "plugins.machinemanagers.%s" % self.config.machine_manager
        try:
            __import__(name, globals(), locals(), ["dummy"], -1)
        except ImportError as e:
            sys.exit("Unable to import machime manager plugin: %s" % e)

        MachineManager()
        module = MachineManager.__subclasses__()[0]
        self.manager = module()
        self.manager.initialize()

        if len(self.manager.machines) == 0:
            sys.exit("No machines")
        else:
            MACHINES = self.manager.machines
            print "Loader %s machine/s" % len(self.manager.machines)

    def stop(self):
        self.running = False

    def start(self):
        self.initialize()

        while self.running:
            time.sleep(1)
            task = self.db.fetch()

            if not task:
                print "No pending tasks"
                continue

            analysis = AnalysisManager(task)
            analysis.start()
