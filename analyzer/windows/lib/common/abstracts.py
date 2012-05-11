class Package(object):
    def __init__(self, options=None):
        if not options:
            return

        self.options = options

    def run(self, path=None):
        raise NotImplementedError

    def check(self):
        raise NotImplementedError

    def finish(self):
        raise NotImplementedError
