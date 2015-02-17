# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys
import pymongo

from django.conf import settings
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.views.decorators.http import require_safe

sys.path.append(settings.CUCKOO_PATH)

import lib.cuckoo.common.compare as compare

results_db = pymongo.MongoClient(settings.MONGO_HOST, settings.MONGO_PORT)[settings.MONGO_DB]

@require_safe
def left(request, left_id):
    left = results_db.analysis.find_one({"info.id": int(left_id)}, {"target": 1, "info": 1})
    if not left:
        return render_to_response("error.html",
                                  {"error": "No analysis found with specified ID"},
                                  context_instance=RequestContext(request))

    # Select all analyses with same file hash.
    records = results_db.analysis.find(
        {
            "$and": [
                {"target.file.md5": left["target"]["file"]["md5"]},
                {"info.id": {"$ne": int(left_id)}}
            ]
        },
        {"target": 1, "info": 1}
    )

    return render_to_response("compare/left.html",
                              {"left": left, "records": records},
                              context_instance=RequestContext(request))

@require_safe
def hash(request, left_id, right_hash):
    left = results_db.analysis.find_one({"info.id": int(left_id)}, {"target": 1, "info": 1})
    if not left:
        return render_to_response("error.html",
                                  {"error": "No analysis found with specified ID"},
                                  context_instance=RequestContext(request))

    # Select all analyses with same file hash.
    records = results_db.analysis.find(
        {
            "$and": [
                {"target.file.md5": right_hash},
                {"info.id": {"$ne": int(left_id)}}
            ]
        },
        {"target": 1, "info": 1}
    )

    # Select all analyses with specified file hash.
    return render_to_response("compare/hash.html",
                              {"left": left, "records": records, "hash": right_hash},
                              context_instance=RequestContext(request))

@require_safe
def both(request, left_id, right_id):
    left = results_db.analysis.find_one({"info.id": int(left_id)}, {"target": 1, "info": 1})
    right = results_db.analysis.find_one({"info.id": int(right_id)}, {"target": 1, "info": 1})

    # Execute comparison.
    counts = compare.helper_percentages_mongo(results_db, left_id, right_id)

    return render_to_response("compare/both.html",
                              {"left": left, "right": right, "left_counts": counts[left_id],
                               "right_counts": counts[right_id]},
                               context_instance=RequestContext(request))
