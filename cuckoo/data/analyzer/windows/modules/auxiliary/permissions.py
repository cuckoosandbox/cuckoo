import logging
from subprocess import call, STARTUPINFO, STARTF_USESHOWWINDOW
from threading import Thread

from lib.common.abstracts import Auxiliary

log = logging.getLogger(__name__)


class Permissions(Auxiliary):
    """
    Change permissions for injected directory and Python interpreter
    to prevent malware from messing with analysis
    """
    def start(self):
        if "permissions" in self.options:
            if not int(self.options["permissions"]):
                return

        locations = ["C:\\Python27", self.analyzer.path, "C:\\WindowsAzure"]
        log.debug("Adjusting permissions for %s", locations)
        for location in locations:

            # First add a non-inherited permission for Admin Read+Execute
            # icacls <location> /grant:r "BUILTIN\Administrators:(OI)(CI)(RX)" "BUILTIN\\Administrators:(RX)" /t /c /q
            modify_admin_params = ["icacls", location, "/grant:r", "BUILTIN\\Administrators:(OI)(CI)(RX)", "BUILTIN\\Administrators:(RX)", "/t", "/c", "/q"]
            t1 = Thread(target=call, args=(modify_admin_params,), kwargs={"startupinfo": self.startupinfo})
            t1.start()
            t1.join(timeout=15)
            if t1.is_alive():
                log.warning("'Modify admin' call was unable to complete in 15 seconds")

            # Then remove all inherited permissions so that only SYSTEM has Write access
            # icacls <location> /inheritancelevel:r /t /c /q
            inheritance_params = ["icacls", location, "/inheritancelevel:r", "/t", "/c", "/q"]
            t2 = Thread(target=call, args=(,), kwargs={"pinfo})
            t2.start()
            t2.join(timeout=15)
            if t2.is_alive():
                log.warning("'Inheritance' call was unable to complete in 15 seconds")

    def __init__(self, options={}, analyzer=None):
        Auxiliary.__init__(self, options, analyzer)
        self.startupinfo = STARTUPINFO()
        self.startupinfo.dwFlags |= STARTF_USESHOWWINDOW
