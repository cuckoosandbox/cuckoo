# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import threading
import socket
import uuid

from cuckoo.common.config import config
from cuckoo.core.database import Database
from cuckoo.machinery.virtualbox import VirtualBox
from cuckoo.web.utils import csrf_exempt
from django.http import HttpResponse, StreamingHttpResponse
from guacamole.client import GuacamoleClient

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

        # TODO: return appropriate error messages to js frontend here
        if not config("cuckoo:remotecontrol:enabled"):
            return HttpResponse(status=404)

        if task.options.get("remotecontrol") != "yes":
            return HttpResponse(status=404)

        if task.status != "running":
            return HttpResponse(status=404)

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
    def _do_connect(task):
        # TODO: way to get to the actual used machinery object
        machinery = VirtualBox()  # hardcoded for virtualbox poc
        params = machinery.get_remote_control_params(task.guest.label)
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
