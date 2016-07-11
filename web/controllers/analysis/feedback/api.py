# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from controllers.analysis.feedback.feedback import AnalysisFeedBackController

class FeedbackApi:
    @staticmethod
    @csrf_exempt
    @require_http_methods(["POST"])
    def send(request):
        if not request.is_ajax():
            return JsonResponse({'status': False}, status=200)

        body = json.loads(request.body)

        task_id = body.get('task_id', None)
        email = body.get('email', '')
        message = body.get('message', '')

        include_analysis = body.get('include_analysis', False)
        include_memdump = body.get('include_memdump', False)

        if not task_id or not isinstance(task_id, int):
            raise Exception('invalid task_id')

        for required in ['email', 'message']:
            if not required in globals() or len(globals()[required]) <= 5:
                raise Exception('%s is required' % required)

        feedback = AnalysisFeedBackController(task_id)
        feedback.email = email
        feedback.message = message
        feedback.include_analysis = include_analysis
        feedback.include_memdump = include_memdump

        identifier = feedback.send()

        return JsonResponse({'status': True, 'feedback_id': identifier}, safe=False)
