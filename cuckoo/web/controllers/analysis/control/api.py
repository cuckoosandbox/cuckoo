# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cuckoo.web.controllers.analysis.control.control import AnalysisControlController
from cuckoo.web.utils import csrf_exempt
from django.http import HttpResponse


class ControlApi:
    @staticmethod
    @csrf_exempt
    def tunnel(request, task_id):
        qs = request.META['QUERY_STRING']

        if qs == 'connect':
            return AnalysisControlController.do_connect(int(task_id))
        else:
            try:
                cmd, conn, = qs.split(':')[:2]
            except ValueError:
                return HttpResponse(status=400)

            if cmd == 'read':
                return AnalysisControlController.do_read(conn)
            elif cmd == 'write':
                return AnalysisControlController.do_write(request, conn)

        return HttpResponse(status=400)
