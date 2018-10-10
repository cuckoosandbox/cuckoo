import logging
import os
import time
import threading

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)

__author__  = "@FernandoDoming"
__version__ = "1.0.0"

class Sysmon(threading.Thread, Auxiliary):

    def clear_log(self):
        try:
            os.system("C:\\Windows\\System32\\wevtutil.exe clear-log microsoft-windows-sysmon/operational")
        except Exception as e:
            log.error("Error clearing Sysmon events - %s" % e)


    def collect_logs(self):
        try:
            os.system("C:\\Windows\\System32\\wevtutil.exe query-events "\
                      "microsoft-windows-sysmon/operational /format:xml /e:Events > C:\\sysmon.xml")
        except Exception as e:
            log.error("Could not create sysmon log file - %s" % e)

        # Give it some time to create the file
        time.sleep(5)

        if os.path.exists("C:\\sysmon.xml"):
            upload_to_host("C:\\sysmon.xml", "sysmon/%s.sysmon.xml" % time.time())
        else:
            log.error("Sysmon log file not found in guest machine")


    def run(self):
        self.clear_log()
        while self.do_run:
            self.collect_logs()
            time.sleep(15)

        return True

    def stop(self):
        self.do_run = False
        self.collect_logs()
        return True

    def __init__(self, options={}, analyzer=None):
        threading.Thread.__init__(self)
        Auxiliary.__init__(self, options, analyzer)
        self.do_run = True
