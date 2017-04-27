import os

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

class Py(Package):
    """Python analysis package."""

    def get_path(self):
        root = os.getenv("homedrive") + '\\'
        paths = [
            os.path.join(root, "Python24", "python.exe"),
            os.path.join(root, "Python25", "python.exe"),
            os.path.join(root, "Python26", "python.exe"),
            os.path.join(root, "Python27", "python.exe"),
            os.path.join(root, "Python32", "python.exe"),
            os.path.join(root, "Python33", "python.exe"),
            os.path.join(root, "Python34", "python.exe"),
        ]

        for path in paths:
            if os.path.exists(path):
                return path

        return None

    def start(self, path):
        python = self.get_path()
        if not python:
            raise CuckooPackageError("Unable to find any Python "
                                     "executable available")

        dll = self.options.get("dll", None)
        free = self.options.get("free", False)
        suspended = True
        if free:
            suspended = False

        p = Process()
        if not p.execute(path=python, args=path, suspended=suspended):
            raise CuckooPackageError("Unable to execute initial Java "
                                     "process, analysis aborted")

        if not free and suspended:
            p.inject(dll)
            p.resume()
            return p.pid
        else:
            return None

    def check(self):
        return True

    def finish(self):
        if self.options.get("procmemdump", False):
            for pid in self.pids:
                p = Process(pid=pid)
                p.dump_memory()

        return True
