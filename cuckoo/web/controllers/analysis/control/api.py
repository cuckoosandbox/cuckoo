# Copyright (C) 2017-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import base64
import logging
import threading
import socket
import uuid

from django.http import HttpResponse, StreamingHttpResponse, JsonResponse
from guacamole.client import GuacamoleClient, GuacamoleError

from cuckoo.common.config import config
from cuckoo.common.objects import File
from cuckoo.core.database import Database
from cuckoo.reporting.mongodb import MongoDB
from cuckoo.misc import cwd
from cuckoo.web.utils import json_error_response, api_post

# TODO Yes, this is far from optimal. In the future we should find a better
# way to get results from the Cuckoo Web Interface to the analysis report (or
# simply disable this functionality altogether).
mdb = MongoDB()
mdb.init_once()

db = Database()
log = logging.getLogger(__name__)

sockets = {}
sockets_lock = threading.RLock()
read_lock = threading.RLock()
write_lock = threading.RLock()
pending_read_request = threading.Event()

class ControlApi(object):
    @staticmethod
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
    def get_report(task_id):
        return mdb.db.analysis.find_one({
            "info.id": int(task_id)
        })

    @api_post
    def store_screenshots(request, task_id, body):
        if not body or not isinstance(body, list):
            return json_error_response("screenshots missing")

        report = ControlApi.get_report(int(task_id))

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
                    raise ValueError

                f = base64.b64decode(b64)
                if f[:4] != "\x89PNG":
                    raise ValueError
            except ValueError:
                return json_error_response("invalid format")

            shot_path = cwd(
                "shots", "remotecontrol_%d.png" % int(sid),
                analysis=int(task_id)
            )
            open(shot_path, "wb").write(f)

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
        if not task.guest:
            return JsonResponse({
                "status": "failed",
                "message": "task is not assigned to a machine yet",
            }, status=500)

        machine = db.view_machine_by_label(task.guest.label)
        rcparams = machine.rcparams

        protocol = rcparams.get("protocol")
        host = rcparams.get("host")
        port = rcparams.get("port")

        guacd_host = config("cuckoo:remotecontrol:guacd_host")
        guacd_port = config("cuckoo:remotecontrol:guacd_port")

        try:
            guac = GuacamoleClient(guacd_host, guacd_port, debug=False)
            guac.handshake(protocol=protocol, hostname=host, port=port)
        except (socket.error, GuacamoleError) as e:
            log.error(
                "Failed to connect to guacd on %s:%d -> %s",
                guacd_host, guacd_port, e
            )
            return JsonResponse({
                "status": "failed",
                "message": "connection failed",
            }, status=500)

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
                        yield guac.receive()
                    except socket.timeout:
                        break

                    if pending_read_request.is_set():
                        break

                # End-of-instruction marker.
                yield "0.;"

        response = StreamingHttpResponse(
            content(), content_type="application/octet-stream"
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
