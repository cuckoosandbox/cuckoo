# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.shortcuts import render

from controllers.analysis.compare.compare import AnalysisCompareController
from bin.utils import view_error

class AnalysisCompareRoutes:
    @staticmethod
    def left(request, task_id):
        try:
            data = AnalysisCompareController.left(task_id)
            return render(request, "analysis/pages/compare/left.html", data)
        except Exception as e:
            return view_error(request, str(e))

    @staticmethod
    def hash(request, task_id, compare_with_hash):
        """Select all analyses with specified file hash."""
        try:
            data = AnalysisCompareController.hash(task_id, compare_with_hash)
            return render(request, "analysis/pages/compare/hash.html", data)
        except Exception as e:
            return view_error(request, str(e))

    @staticmethod
    def both(request, task_id, compare_with_task_id):
        try:
            data = AnalysisCompareController.both(task_id, compare_with_task_id)
            return render(request, "analysis/pages/compare/both.html", data)
        except Exception as e:
            return view_error(request, str(e))
