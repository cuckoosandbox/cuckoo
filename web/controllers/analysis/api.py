# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import pymongo

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from lib.cuckoo.core.database import Database, Task


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

        filters = {
            "info.category": {"$in": cats}
        }

        if isinstance(score_range, (str, unicode)) and score_range != '':
            if "-" not in score_range:
                raise Exception("faulty score")

            score_min, score_max = score_range.split('-', 1)

            try:
                score_min = int(score_min)
                score_max = int(score_max)

                if score_min < 0 or score_min > 10 or score_max < 0 or score_max > 10:
                    raise Exception('faulty score')
            except:
                raise Exception('faulty score')

            filters["info.score"] = {"$gte": score_min, "$lte": score_max}

        cursor = results_db.analysis.find(
            filters, sort=[("_id", pymongo.DESCENDING)]
        ).limit(limit).skip(offset)

        tasks = []
        for row in cursor:
            tasks.append({
                'ended': row['info']['ended'],
                'score': row['info']['score'],
                'id': row['info']['id']
            })

        if tasks:
            db = Database()
            q = db.Session().query(Task)

            q = q.filter(Task.id.in_([z['id'] for z in tasks]))

            for task_sql in q.all():
                for task_mongo in [z for z in tasks if z['id'] == task_sql.id]:
                    task_mongo['sample'] = task_sql.sample.to_dict()

                    if task_sql.category == 'file':
                        task_mongo['filename_url'] = os.path.basename(task_sql.target)
                    elif task_sql.category == 'url':
                        task_mongo['filename_url'] = task_sql.target

                    task_mongo.update(task_sql.to_dict())

        return JsonResponse(tasks, safe=False)
