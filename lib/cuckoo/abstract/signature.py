class Signature(object):
    def __init__(self):
        self.info = {"name" : "",
                     "description" : "",
                     "severity" : 1,
                     "references" : [],
                     "author" : []}
        self.alert = False
        self.enabled = True
        self.data = []

    def run(self, results=None):
        raise NotImplementedError
