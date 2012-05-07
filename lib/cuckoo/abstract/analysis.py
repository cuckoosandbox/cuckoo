import os

class Analysis(object):
    def __init__(self):
        self.analysis_path = ""
        self.logs_path = ""

    def set_path(self, analysis_path):
        self.analysis_path = analysis_path
        self.logs_path = os.path.join(analysis_path, "logs")

    def run(self):
        raise NotImplementedError
