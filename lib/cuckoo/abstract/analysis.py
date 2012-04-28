class Analysis(object):
    def __init__(self, analysis_path=None):
        if not analysis_path:
            return

    def run(self):
        raise NotImplementedError
