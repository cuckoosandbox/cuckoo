from lib.abstract.package import Package
from lib.api.process import Process

class Exe(Package):
    def run(self, path):
        p = Process()
        p.execute(path=path, suspended=True)
        p.inject()
        p.resume()

        return p.pid

    def check(self):
        return True

    def finish(self):
        return True
