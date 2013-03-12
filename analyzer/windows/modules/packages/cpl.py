import shutil

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

class Cpl(Package):
    """CPL Control Panel files analysis package."""

    def start(self, path):
        free = self.options.get("free", False)
        function = self.options.get("function", None)
        suspended = True
        if free:
            suspended = False

        # file need the .cpl extention to execute
        cplpath = "%s.cpl" % path
        shutil.copyfile(path, cplpath)

        if function:
            args = "shel32.dll.Control_RunDLL %s,%s" % (cplpath, function)
        else:
            args = "shel32.dll.Control_RunDLL %s" % cplpath

        p = Process()
        if not p.execute(path="C:\\WINDOWS\\system32\\rundll32.exe", args=args, suspended=suspended):
            raise CuckooPackageError("Unable to execute rundll32, analysis aborted")

        if not free and suspended:
            p.inject()
            p.resume()
            return p.pid
        else:
            return None

    def check(self):
        return True

    def finish(self):
        return True
