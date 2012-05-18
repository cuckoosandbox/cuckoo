from lib.common.abstracts import Package
from lib.api.process import Process

class XLS(Package):
    def run(self, path):
        arg = "\"%s\"" % path
        p = Process()
        p.execute(path="C:\\Program Files\\Microsoft Office\\Office12\\EXCEL.EXE", args=arg, suspended=True)
        p.inject()
        p.resume()

        return p.pid

    def check(self):
        return True

    def finish(self):
        return True
