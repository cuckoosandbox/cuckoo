# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging

from django.shortcuts import render_to_response
from django.template import RequestContext

from cuckoo.common.exceptions import CuckooFeedbackError
from cuckoo.core.feedback import CuckooFeedback

log = logging.getLogger(__name__)

def handler404(request):
    response = render_to_response(
        "errors/error.html", {
            "code": 404,
            "error": "Sorry, but the page you are looking for was not found."
        }, context_instance=RequestContext(request)
    )
    response.status_code = 404
    return response

def handler500(request):
    response = render_to_response(
        "errors/error.html", {
            "code": 500,
            "error": "A server error occurred."
        }, context_instance=RequestContext(request)
    )
    response.status_code = 500
    return response

class ExceptionMiddleware(object):
    def process_exception(self, request, exception):
        try:
            feedback = CuckooFeedback()
            feedback.send_exception(exception, request)
        except CuckooFeedbackError as e:
            log.warning(
                "Error providing feedback to the backend: %s" % e
            )
