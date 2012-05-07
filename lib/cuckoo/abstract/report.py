import os

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
