# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

import logging
import threading
import uuid

from cuckoo.common.config import config
from cuckoo.machinery.virtualbox import VirtualBox
from django.http import StreamingHttpResponse, HttpResponse
from guacamole.client import GuacamoleClient

log = logging.getLogger(__name__)

sockets = {}
sockets_lock = threading.RLock()
read_lock = threading.RLock()
write_lock = threading.RLock()
pending_read_request = threading.Event()


class AnalysisControlController:
    @staticmethod
    def do_connect(task):
        # TODO: way to get to the actual used machinery object
        machinery = VirtualBox()  # hardcoded for virtualbox poc
        params = machinery.get_remote_control_params(task.guest.label)
        protocol, hostname, port = params

        guacd_host = config("cuckoo:remotecontrol:guacd_host")
        guacd_port = config("cuckoo:remotecontrol:guacd_port")

        guac = GuacamoleClient(guacd_host, guacd_port, debug=False)
        guac.handshake(protocol=protocol, hostname=hostname, port=port)

        cache_key = str(uuid.uuid4())
        with sockets_lock:
            sockets[cache_key] = guac

        response = HttpResponse(content=cache_key)
        response['Cache-Control'] = 'no-cache'

        return response

    @staticmethod
    def do_read(cache_key):
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
    def do_write(request, cache_key):
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
