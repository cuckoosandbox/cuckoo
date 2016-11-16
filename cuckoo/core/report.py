# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from functools import wraps

from django.conf import settings

from controllers.analysis.analysis import AnalysisController

class AbstractReport:
    def __init__(self, analysis_id):
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
        return self.get("analysis", "path")

    @property
    def test(self):
        return self.get("analysis", "info", "id")

    @property
    def analysis_feedback(self):
        return self.get("analysis", "feedback")

    @property
    def analysis_target(self):
        return self.get("analysis", "target")

    @property
    def analysis_errors(self):
        return self.get("analysis", "debug", "errors")

    def get(self, key, *keys):
        """Safe report.json dict lookup"""
        def _inner(dic, _key, *_keys):
            if _keys:
                return _inner(dic.get(_key, {}), *_keys)
            return dic.get(_key, {})
        return _inner(self.src, key, *keys)
