# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

class Report(object):
    def __init__(self, report):
        self.report = report

    def get(self, *keys):
        r = self.report
        for key in keys:
            if key not in r:
                return
            r = r[key]
        return r

    @property
    def info(self):
        return self.get("info") or {}

    @property
    def path(self):
        return self.get("info", "analysis_path")

    @property
    def feedback(self):
        return self.get("feedback") or {}

    @property
    def target(self):
        return self.get("target")

    @property
    def errors(self):
        return self.get("debug", "errors") or []
