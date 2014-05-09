# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys

from django.conf import settings
from django.shortcuts import render_to_response
from django.template import RequestContext

sys.path.append(settings.CUCKOO_PATH)

from utils.health_statistics import HealthStatistics


def index(request):
    hs = HealthStatistics(simple=True)
    stat_items = [("Processing stages",
                   "Time spent in the separate processing stages",
                   "generated/" + hs.processing_stages_pie()),
                  ("Processing time",
                   "Number of samples vs processing time",
                   "generated/" + hs.processing_time_line()),
                  ("Task status",
                   "Percent of samples in specific states",
                   "generated/" + hs.task_status_pie()),
                  ("Success by machine",
                   "Task success by machine to identify damaged machines",
                   "generated/" + hs.task_success_by_machine_bar()),
                  ("Analysis issues",
                   "Task analysis issues, global\nAnti issues are just logging if a sample tried something, we do not know if it was successfull",
                   "generated/" + hs.task_analysis_pie()),
                  ("Analysis issues by machine",
                   "Task analysis issues, sorted by machine",
                   "generated/" + hs.task_analysis_by_machine_bar()),
                  ("Analysis issues by file type",
                   "Task analysis issues, sorted by file type",
                   "generated/" + hs.analysis_issues_by_file_type())]

    return render_to_response("statistics/index.html",
                              {"stat_items": stat_items},
                              context_instance=RequestContext(request))