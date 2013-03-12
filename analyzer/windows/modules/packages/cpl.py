from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

class Cpl(Package):
    """CPL Control Panel analysis package."""

    def start(self, path):
        free = self.options.get("free", False)
        function = self.options.get("function", None)
        suspended = True
        if free:
            suspended = False

        if function:
            args = "/c %s,%s" % (path, function)
        else:
            args = "/c %s" % path

        p = Process()
        if not p.execute(path="C:\\WINDOWS\\system32\\cmd.exe", args=args, suspended=suspended):
            raise CuckooPackageError("Unable to execute cmd.exe, analysis aborted")

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
