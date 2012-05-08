class Package(object):
    def run(self, path=None):
        raise NotImplementedError

    def check(self):
        raise NotImplementedError

    def finish(self):
        raise NotImplementedError
