# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from functools import wraps

from django.conf import settings

from controllers.analysis.analysis import AnalysisController

class Report:
    def __init__(self, analysis_id):
        self.analysis_id = analysis_id
        self.mongo = settings.MONGO
        self.report = AnalysisController.get_report(analysis_id)

    def analaysis_id(self):
        return self.safe_lookup("analysis", "id")

    def analysis_path(self):
        return self.safe_lookup("analysis", "path")

    @property
    def test(self):
        return self.safe_lookup("analysis", "path")

    def analysis_feedback(self):
        return self.safe_lookup("analysis", "feedback")

    def analysis_target(self):
        return self.lookup("analysis", "target")

    def analysis_errors(self, report):
        pass

    def safe_lookup(self, key, *keys):
        def _inner(dic, _key, *_keys):
            if _keys:
                return _inner(dic.get(_key, {}), *_keys)
            return dic.get(_key)
        return _inner(self.report, key, *keys)
