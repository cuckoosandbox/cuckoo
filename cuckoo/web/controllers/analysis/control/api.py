# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import base64
import logging
import threading
import os
import socket
import uuid

from cuckoo.common.config import config
from cuckoo.common.objects import File
from cuckoo.core.database import Database
from cuckoo.reporting.mongodb import MongoDB
from cuckoo.machinery.virtualbox import VirtualBox
from cuckoo.misc import cwd
from cuckoo.web.utils import csrf_exempt, json_error_response, api_post
from django.http import HttpResponse, StreamingHttpResponse, JsonResponse
from guacamole.client import GuacamoleClient

mdb = MongoDB()
mdb.init_once()
db = Database()
log = logging.getLogger(__name__)

sockets = {}
sockets_lock = threading.RLock()
read_lock = threading.RLock()
write_lock = threading.RLock()
pending_read_request = threading.Event()


class ControlApi:
    @staticmethod
    @csrf_exempt
    def tunnel(request, task_id):
        task = db.view_task(int(task_id))
        if not task:
            return HttpResponse(status=404)

        if not config("cuckoo:remotecontrol:enabled"):
            return JsonResponse({
                "status": "failed",
                "msg": "remote control is not enabled",
            }, status=500)

        if task.options.get("remotecontrol") != "yes":
            return JsonResponse({
                "status": "failed",
                "msg": "this task does not have remote control",
            }, status=500)

        if task.status != "running":
            return JsonResponse({
                "status": task.status,
                "msg": "this task is not running",
            }, status=500)

        qs = request.META["QUERY_STRING"]
        if qs == "connect":
            return ControlApi._do_connect(task)
        else:
            try:
                cmd, conn, = qs.split(":")[:2]
            except ValueError:
                return HttpResponse(status=400)

            if cmd == "read":
                return ControlApi._do_read(conn)
            elif cmd == "write":
                return ControlApi._do_write(request, conn)

        return HttpResponse(status=400)

    @staticmethod
    def task_status(request, task_id):
        task = db.view_task(int(task_id))
        if not task:
            return HttpResponse(status=404)

        return JsonResponse({
            "task_status": task.status,
        })

    @api_post
    def store_screenshots(request, task_id, body):
        if not body or not isinstance(body, list):
            return json_error_response("screenshots missing")

        report = mdb.db.analysis.find_one({
            "info.id": int(task_id),
        })

        if not report:
            return json_error_response("report missing")

        for scr in body:
            sid = scr.get("id", None)
            data = scr.get("data", None)

            try:
                if sid is None or not data:
                    raise ValueError

                ftype, b64 = data.split(",")
                if ftype != "data:image/png;base64":
                    raise ValueError()

                f = base64.b64decode(b64)
                if f[:4] != "\x89PNG":
                    raise ValueError()
            except ValueError:
                return json_error_response("invalid format")

            scr_dir = os.path.join(
                cwd(), "storage", "analyses",
                "%d" % int(task_id), "shots",
            )
            shot_file = "remotecontrol_%d.png" % int(sid)
            shot_path = os.path.join(scr_dir, shot_file)

            with open(shot_path, "wb") as sf:
                sf.write(f)

            shot_blob = {}
            shot = File(shot_path)
            if shot.valid():
                shot_id = mdb.store_file(shot)
                shot_blob["original"] = shot_id

            if shot_blob:
                report["shots"].append(shot_blob)

        mdb.db.analysis.save(report)
        return JsonResponse({
            "status": "success",
        })


    @staticmethod
    def _do_connect(task):
        # TODO: store connection details in the task and grab them from there
        params = ("rdp", "localhost", 4444)
        protocol, hostname, port = params

        guacd_host = config("cuckoo:remotecontrol:guacd_host")
        guacd_port = config("cuckoo:remotecontrol:guacd_port")

        guac = GuacamoleClient(guacd_host, guacd_port, debug=False)
        try:
            guac.handshake(protocol=protocol, hostname=hostname, port=port)
        except socket.error:
            log.error(
                "Failed to connect to guacd on %s:%d"
                % (guacd_host, guacd_port)
            )
            return HttpResponse(status=500)

        cache_key = str(uuid.uuid4())
        with sockets_lock:
            sockets[cache_key] = guac

        response = HttpResponse(content=cache_key)
        response["Cache-Control"] = "no-cache"

        return response

    @staticmethod
    def _do_read(cache_key):
        pending_read_request.set()

        def content():
            with sockets_lock:
                guac = sockets[cache_key]
            with read_lock:
                pending_read_request.clear()

                while True:
                    try:
                        content = guac.receive()
                        if content:
                            yield content
                        else:
                            break
                    except Exception:
                        break

                    if pending_read_request.is_set():
                        break
                # End-of-instruction marker
                yield "0.;"

        response = StreamingHttpResponse(
            content(),
            content_type="application/octet-stream"
        )

        response["Cache-Control"] = "no-cache"
        return response

    @staticmethod
    def _do_write(request, cache_key):
        with sockets_lock:
            guac = sockets[cache_key]

        with write_lock:
            while True:
                chunk = request.read(8192)
                if chunk:
                    guac.send(chunk)
                else:
                    break

        response = HttpResponse(content_type="application/octet-stream")
        response["Cache-Control"] = "no-cache"
        return response
