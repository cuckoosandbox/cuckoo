# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys

from django.conf import settings
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.views.decorators.http import require_safe

import pymongo

sys.path.append(settings.CUCKOO_PATH)

results_db = pymongo.connection.Connection(settings.MONGO_HOST, settings.MONGO_PORT).cuckoo

@require_safe
def left(request, left_id):
    # Select all analyses with same file hash.
    original = results_db.analysis.find_one({"info.id" : int(left_id)}, {"target" : 1, "info" : 1})

    if not original:
        return render_to_response("error.html",
                                  {"error" : "No analysis found with specified ID"},
                                  context_instance=RequestContext(request))

    records = results_db.analysis.find({"target.file.md5" : original["target"]["file"]["md5"]}, {"target" : 1, "info" : 1})

    return render_to_response("compare/left.html",
                              {"original" : original, "records" : records},
                              context_instance=RequestContext(request))

@require_safe
def hash(request, left_id, right_hash):
    # Select all analyses with specified file hash.
    return render_to_response("compare/hash.html",
                              context_instance=RequestContext(request))
@require_safe
def both(request, left_id, right_id):
    # Execute comparison.
    return render_to_response("compare/both.html",
                              context_instance=RequestContext(request)) 

@require_safe
def index(request):
    return render_to_response("compare/index.html",
                              context_instance=RequestContext(request))
