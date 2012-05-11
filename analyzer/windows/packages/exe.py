from lib.common.abstracts import Package
from lib.api.process import Process

class Exe(Package):
    def run(self, path):
        p = Process()

        if "arguments" in self.options:
            p.execute(path=path, args=self.options["arguments"], suspended=True)
        else:
            p.execute(path=path, suspended=True)

        p.inject()
        p.resume()

        return p.pid

    def check(self):
        return True

    def finish(self):
        return True
