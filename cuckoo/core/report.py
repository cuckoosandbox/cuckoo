# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.conf import settings

from cuckoo.web.controllers.analysis.analysis import AnalysisController

class AbstractDict(object):
    def __init__(self):
        self.src = {}

    def get(self, *keys):
        """Safe nested lookup"""
        return reduce(lambda d, key: d.get(key) if d else None, keys, self.src)

    def __getitem__(self, key):
        return self.src[key]

class AbstractReport(AbstractDict):
    def __init__(self, analysis_id):
        super(AbstractReport, self).__init__()
        self.mongo = settings.MONGO
        self.src = AnalysisController.get_report(analysis_id)

    @property
    def analysis(self):
        return self.get("analysis")

    @property
    def analysis_info(self):
        return self.get("analysis", "info")

    @property
    def analysis_id(self):
        return self.get("analysis", "info", "id")

    @property
    def analysis_path(self):
        return self.get("analysis", "info", "analysis_path")

    @property
    def analysis_feedback(self):
        return self.get("analysis", "feedback")

    @property
    def analysis_target(self):
        return self.get("analysis", "target")

    @property
    def analysis_errors(self):
        return self.get("analysis", "debug", "errors")
