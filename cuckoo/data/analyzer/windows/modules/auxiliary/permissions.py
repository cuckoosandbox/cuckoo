import logging
from subprocess import call, STARTUPINFO, STARTF_USESHOWWINDOW

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
            call(modify_admin_params, startupinfo=self.startupinfo)

            # Then remove all inherited permissions so that only SYSTEM has Write access
            # icacls <location> /inheritancelevel:r /t /c /q
            inheritance_params = ["icacls", location, "/inheritancelevel:r", "/t", "/c", "/q"]
            call(inheritance_params, startupinfo=self.startupinfo)

    def __init__(self, options={}, analyzer=None):
        Auxiliary.__init__(self, options, analyzer)
        self.startupinfo = STARTUPINFO()
        self.startupinfo.dwFlags |= STARTF_USESHOWWINDOW
