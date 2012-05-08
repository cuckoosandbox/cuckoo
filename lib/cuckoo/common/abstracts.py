import os

class Dictionary(dict):
    def __getattr__(self, key):
        return self.get(key, None)

    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

class MachineManager(object):
    def initialize(self):
        pass

    def acquire(self, label=None):
        raise NotImplementedError

    def release(self, label=None):
        raise NotImplementedError

    def start(self, label=None):
        raise NotImplementedError

    def stop(self, label=None):
        raise NotImplementedError

class Analysis(object):
    def __init__(self):
        self.analysis_path = ""
        self.logs_path = ""

    def set_path(self, analysis_path):
        self.analysis_path = analysis_path
        self.logs_path = os.path.join(analysis_path, "logs")

    def run(self):
        raise NotImplementedError

class Signature(object):
    name = ""
    description = ""
    severity = 1
    references = []
    alert = False
    enabled = True

    def __init__(self):
        self.data = []

    def run(self, results=None):
        raise NotImplementedError
        
class Report(object):
    def __init__(self):
        self.analysis_path = ""
        self.reports_path = ""
        self.options = None

    def set_path(self, analysis_path):
        self.analysis_path = analysis_path
        self.reports_path = os.path.join(self.analysis_path, "reports")

        if not os.path.exists(self.reports_path):
            os.mkdir(self.reports_path)

    def set_options(self, options):
        self.options = options

    def run(self):
        raise NotImplementedError
