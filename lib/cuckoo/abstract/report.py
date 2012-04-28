class Report(object):
    def __init__(self, analysis_path):
        self.analysis_path = analysis_path
        self.options = None

    def set_options(self, options):
        self.options = options

    def run(self)
        raise NotImplementedError
