# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import json
import subprocess
from PIL import Image
import pymongo

from lib.cuckoo.common.abstracts import Processing
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from lib.cuckoo.core.database import Database, Task
from controllers.analysis.analysis import AnalysisController


results_db = settings.MONGO


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

        # filters
        cats = body.get('cats')
        packs = body.get('packs')
        score_range = body.get('score', None)

        filters = {}

        if isinstance(score_range, (str, unicode)):
            if not '-' in score_range:
                raise Exception('')

            score_min, score_max = score_range.split('-', 1)

            try:
                score_min = int(score_min)
                score_max = int(score_max)

                if score_min < 0 or score_min > 10 or score_max < 0 or score_max > 10:
                    raise Exception()
            except:
                raise Exception('Faulty score(s)')

            filters["info.score"] = [{"info.score": {"$gte": score_min}}, {"info.score": {"$lte": score_max}}]

        cursor = results_db.analysis.find(filters, sort=[("_id", pymongo.DESCENDING)]).limit(limit).skip(offset)

        data = {}
        for row in cursor:
            data[row['info']['id']] = {
                'ended': row['info']['ended'],
                'score': row['info']['score'],
            }

        if data:
            db = Database()
            q = db.Session().query(Task)

            q = q.filter(Task.id.in_(data.keys()))

            for task in q.all():
                data[task.id].update(task.to_dict())
                data[task.id]['sample'] = task.sample.to_dict()

        return JsonResponse(data, safe=False)