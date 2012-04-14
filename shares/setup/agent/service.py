import win32serviceutil
import win32service
import win32event
import servicemanager
import sys
import os


class Service(win32serviceutil.ServiceFramework):
    _svc_name_ = 'CuckooService'
    _svc_display_name_ = 'CuckooService'
    _svc_description_ = 'CuckooService'

    def __init__(self, args):
        self._args = args
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.isAlive = True

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.isAlive = False

    def SvcDoRun(self):
        servicemanager.LogInfoMsg("Started Cuckoo service")
        dir = os.path.join(sys.executable, '..\\..\\..')
        os.chdir(dir)
        os.system('"C:\\Python27\\python.exe analyzer.py"') # TODO: fix python path
        win32event.SetEvent(self.hWaitStop)
        servicemanager.LogInfoMsg("Stopped Cuckoo service")
