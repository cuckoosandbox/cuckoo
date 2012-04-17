from lib.api.process import Process

class Package:
    def run(self, path = None):
        p = Process()
        p.execute("C:\\WINDOWS\\system32\\calc.exe")
        p.inject()

        return p.pid

    def check(self):
        return True

    def finish(self):
        return True
