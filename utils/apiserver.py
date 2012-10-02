#!/usr/bin/env python
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import json
import argparse

from cherrypy import _cpwsgiserver3
from bottle import Bottle, run, request, server_names, ServerAdapter

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.core.database import Database

ERRORS = {
    "ERROR_INVALID_KEY" : "You provided an invalid API key"
}

def jsonize(data):
    return json.dumps(data, sort_keys=False, indent=4)

def report_error(error_code):
    return jsonize({"error" : True, "error_code" : error_code, "error_message" : ERRORS[error_code]})

def verify_key(key):
    if key != "machete":
        return False
    else:
        return True

class SSLServer(ServerAdapter):
    def run(self, handler):
        server = _cpwsgiserver3.CherryPyWSGIServer((self.host, self.port), handler)

        # openssl req -new -x509 -keyout server.pem -out server.pem -nodes
        cert = "server.pem"

        if not os.path.exists(cert):
            print("ERROR: Cannot find SSL certificate at path \"%s\". Abort." % cert)
            return

        server.ssl_certificate = cert
        server.ssl_private_key = cert
        try:
            server.start()
        finally:
            server.stop()

server_names["sslserver"] = SSLServer
app = Bottle()

@app.post("/task/create", method="POST")
def task_create():
    response = {"error" : False}

    key = request.forms.get("key")
    if not verify_key(key):
        return report_error("ERROR_INVALID_KEY")

    package = request.forms.get("package")
    timeout = request.forms.get("timeout")
    priority = request.forms.get("priority")
    options = request.forms.get("options")
    machine = request.forms.get("machine")
    platform = request.forms.get("platform")
    custom = request.forms.get("custom")

    db = Database()
    db.add(file_path="/tmp/a", package=package, timeout=timeout, priority=priority, options=options, machine=machine, platform=platform, custom=custom)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", type=str, action="store", default="localhost", help="Specify the host", required=False)
    parser.add_argument("--port", type=str, action="store", default="8080", help="Specify a port", required=False)
    args = parser.parse_args()

    run(app, host=args.host, port=args.port, server="sslserver")

if __name__ == "__main__":
    main()