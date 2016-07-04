# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import json
import subprocess
from PIL import Image

from lib.cuckoo.common.abstracts import Processing
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from controllers.analysis.analysis import AnalysisController


class AnalysisApi:
    @staticmethod
    @csrf_exempt
    @require_http_methods(["POST"])
    def recent(request):
        if not request.is_ajax():
            return JsonResponse({'status': False}, status=200)

        body = json.loads(request.body)
        limit = body.get('limit', 50)
        offset = body.get('offset', 0)
        score_range = body.get('score_range', "0-10")

        data = AnalysisController().get_recent(
            limit=limit,
            offset=offset)

        return JsonResponse(data, safe=False)