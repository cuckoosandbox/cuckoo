from lib.abstract.package import Package
from lib.api.process import Process

class PDF(Package):
    def run(self, path):
        arg = "\"%s\"" % path
        p = Process()
        p.execute(path="C:\\Program Files\\Adobe\\Reader 9.0\\Reader\\AcroRd32.exe", args=arg, suspended=True)
        p.inject()
        p.resume()

        return p.pid

    def check(self):
        return True

    def finish(self):
        return True
