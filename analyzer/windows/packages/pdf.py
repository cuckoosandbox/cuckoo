from lib.core.defines import *
from lib.api.process import Process

class Package:
    def run(self, path = None):
        p = Process()
        p.execute("C:\\Program Files\\Adobe\\Reader 10.0\\Reader\\AcroRd32.exe", "C:\\a.pdf", suspended=True)
        p.inject()
        p.resume()

        KERNEL32.Sleep(4000)
        p.dump_memory()

        return p.pid

    def check(self):
        return True

    def finish(self):
        return True
