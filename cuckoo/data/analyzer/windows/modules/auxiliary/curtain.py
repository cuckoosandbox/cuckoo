import logging, os, time, threading

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)

__author__  = "Jeff White [karttoon] @noottrak"
__email__   = "jwhite@paloaltonetworks.com"
__version__ = "1.0.3"
__date__    = "21FEB2018"

class Curtain(threading.Thread, Auxiliary):

    def collectLogs(self):

        try:
            os.system("C:\\Windows\\System32\\wevtutil.exe query-events microsoft-windows-powershell/operational /rd:true /e:root /format:xml /uni:true > C:\\curtain.log")
        except Exception as e:
            log.error("Curtain - Error collecting PowerShell events - %s " % e)

        time.sleep(5)

        if os.path.exists("C:\\curtain.log"):
            upload_to_host("C:\\curtain.log", "curtain/%s.curtain.log" % time.time())
        else:
            log.error("Curtain log file not found!")

    def clearLogs(self):

        try:
            os.system("C:\\Windows\\System32\\wevtutil.exe clear-log microsoft-windows-powershell/operational")
        except Exception as e:
            log.error("Curtain - Error clearing PowerShell events - %s" % e)

    def run(self):

        self.clearLogs()

        while self.do_run:

            self.collectLogs()

            time.sleep(15)

        return True

    def stop(self):

        self.collectLogs()

        return True

    def __init__(self, options={}, analyzer=None):
        threading.Thread.__init__(self)
        Auxiliary.__init__(self, options, analyzer)
        self.do_run = True
