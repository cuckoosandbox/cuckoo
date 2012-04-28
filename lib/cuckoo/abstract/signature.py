class Signature(object):
    def __init__(self):
        self.alert   = False
        self.enabled = True
        self.data    = []

    def run(self, results=None):
        raise NotImplementedError
