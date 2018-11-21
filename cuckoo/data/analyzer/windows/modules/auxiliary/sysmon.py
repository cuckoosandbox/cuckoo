import logging
import subprocess
import os
import time

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)

__author__  = "haam3r"
__version__ = "1.0.0"
__date__    = "2018-06-26"

class Sysmon(Auxiliary):
    '''
    Collect Sysmon logs generated during an analysis
    '''

    def __init__(self, options={}, analyzer=None):
        Auxiliary.__init__(self, options, analyzer)

    def start(self):
        # Clear old events from Sysmon log
        log.debug('Clearing Sysmon log')
        try:
            os.system("C:\\Windows\\System32\\wevtutil.exe clear-log microsoft-windows-sysmon/operational")
        except Exception as e:
            log.error("Error clearing Sysmon events - %s" % e)

        return True


    def finish(self):
        # Query events and dump to file
        try:
            os.system("C:\\Windows\\System32\\wevtutil.exe query-events microsoft-windows-sysmon/operational /rd:false /e:root /format:xml /uni:true > C:\\sysmon.log")
        except Exception as e:
            log.error("Sysmon - Could not export sysmon logs")

        if os.path.exists("C:\\sysmon.log"):
            upload_to_host("C:\\sysmon.log", "sysmon/sysmon.xml")
        else:
            log.error("Sysmon log file not found")

        return True

