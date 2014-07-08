# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package

class CPL(Package):
    """Control Panel Applet analysis package."""
    PATHS = [
        ("SystemRoot", "system32", "control.exe"),
    ]

    def start(self, path):
<<<<<<< HEAD
        control = self.get_path()
        if not control:
            raise CuckooPackageError("Unable to find any control.exe "
                                     "executable available")

        dll = self.options.get("dll", None)
        free = self.options.get("free", False)
        suspended = True
        if free:
            suspended = False

        # file need the .cpl extention to execute
        if path.endswith('.cpl'):
            cplpath = path
        else:
            cplpath = "%s.cpl" % path
            os.rename(path, cplpath)

        p = Process()
        if not p.execute(path=control, args="\"%s\"" % cplpath,
                         suspended=suspended):
            raise CuckooPackageError("Unable to execute initial Control "
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
=======
        control = self.get_path("control.exe")
        return self.execute(control, "\"%s\"" % path)
>>>>>>> upstream/master
