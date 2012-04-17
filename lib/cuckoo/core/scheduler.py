import sys
import time

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.database import Database

class Scheduler:
    def __init__(self):
        self.running = True

    def stop(self):
        self.running = False

    def start(self):
        config = Config()
        db     = Database()

        machiner_name = "plugins.machiners.%s" % config.machiner
        try:
            machiner = __import__(machiner_name,
                                  globals(),
                                  locals(),
                                  ["Machiner"],
                                  -1)
        except ImportError as e:
            sys.exit("Unable to import machiner plugin: %s" % e)

        m = machiner.Machiner()
        m.prepare()

        if len(m.machines) == 0:
            sys.exit("No machines")
        else:
            print "Loaded %s machine/s" % len(m.machines)

        while self.running:
            task = db.get_task()

            if not task:
                print "No pending tasks"
                time.sleep(1)
                continue
