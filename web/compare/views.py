# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys

from django.conf import settings
from django.shortcuts import render
from django.views.decorators.http import require_safe

sys.path.insert(0, settings.CUCKOO_PATH)

import lib.cuckoo.common.compare as compare

results_db = settings.MONGO

@require_safe
def left(request, left_id):
    left = results_db.analysis.find_one({"info.id": int(left_id)}, {"target": 1, "info": 1})
    if not left:
        return render(request, "error.html", {
            "error": "No analysis found with specified ID",
        })

    if left["target"]["category"] == "url":
        # Select all analyses for the same URL.
        records = results_db.analysis.find(
            {
                "$and": [
                    {"target.url": left["target"]["url"]},
                    {"info.id": {"$ne": int(left_id)}}
                ]
            },
            {"target": 1, "info": 1}
        )
    else:
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

    return render(request, "compare/left.html", {
        "left": left,
        "records": records,
    })

@require_safe
def hash(request, left_id, right_hash):
    left = results_db.analysis.find_one({"info.id": int(left_id)}, {"target": 1, "info": 1})
    if not left:
        return render(request, "error.html", {
            "error": "No analysis found with specified ID",
        })

    # If the analysis is not of a file, but of a URL, we consider the hash
    # to be a URL instead.
    if left["target"]["category"] == "url":
        records = results_db.analysis.find(
            {
                "$and": [
                    {"target.url": {"$regex": right_hash, "$options": "-i"}},
                    {"info.id": {"$ne": int(left_id)}}
                ]
            },
            {"target": 1, "info": 1}
        )
    else:
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
    return render(request, "compare/hash.html", {
        "left": left,
        "records": records,
        "hash": right_hash,
    })

@require_safe
def both(request, left_id, right_id):
    left = results_db.analysis.find_one({"info.id": int(left_id)}, {"target": 1, "info": 1})
    right = results_db.analysis.find_one({"info.id": int(right_id)}, {"target": 1, "info": 1})

    # Execute comparison.
    counts = compare.helper_percentages_mongo(results_db, left_id, right_id)

    return render(request, "compare/both.html", {
        "left": left,
        "right": right,
        "left_counts": counts[left_id],
        "right_counts": counts[right_id],
    })
