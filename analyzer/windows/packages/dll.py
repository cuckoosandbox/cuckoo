from lib.common.abstracts import Package
from lib.api.process import Process

class Dll(Package):
    def run(self, path):
        p = Process()

        rundll32 = "C:\\WINDOWS\\system32\\rundll32.exe"

        if "function" in self.options:
            p.execute(path=rundll32, args="%s,%s" % (path, self.options["function"]), suspended=True)
        else:
            p.execute(path=rundll32, args="%s,DllMain" % path, suspended=True)

        inject = True
        if "free" in self.options:
            if self.options["free"] == "yes":
                inject = False

        if inject:
            p.inject()

        p.resume()

        return p.pid

    def check(self):
        return True

    def finish(self):
        return True
