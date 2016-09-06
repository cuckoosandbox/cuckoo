from django.shortcuts import render_to_response
from django.template import RequestContext


def handler404(request):
    response = render_to_response(
        'errors/error.html', {
            "code": 404,
            "error": "Sorry, but the page you are looking for was not found."
        }, context_instance=RequestContext(request))
    response.status_code = 404
    return response


def handler500(request):
    response = render_to_response(
        'errors/error.html', {
            "code": 500,
            "error": "A server error occurred."
        }, context_instance=RequestContext(request))
    response.status_code = 500
    return response