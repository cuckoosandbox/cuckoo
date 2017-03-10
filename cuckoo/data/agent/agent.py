#!/usr/bin/env python
# Copyright (C) 2015-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import cgi
import io
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import traceback
import zipfile

import SimpleHTTPServer
import SocketServer

AGENT_VERSION = "0.7"
AGENT_FEATURES = [
    "execpy", "pinning", "logs", "largefile", "unicodepath",
]

sys.stdout = io.BytesIO()
sys.stderr = io.BytesIO()

class MiniHTTPRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    server_version = "Cuckoo Agent"

    def do_GET(self):
        request.client_ip, request.client_port = self.client_address
        request.form = {}
        request.files = {}

        if "client_ip" not in state or request.client_ip == state["client_ip"]:
            self.httpd.handle(self)

    def do_POST(self):
        environ = {
            "REQUEST_METHOD": "POST",
            "CONTENT_TYPE": self.headers.get("Content-Type"),
        }

        form = cgi.FieldStorage(fp=self.rfile,
                                headers=self.headers,
                                environ=environ)

        request.form = {}
        request.files = {}

        # Another pretty fancy workaround. Since we provide backwards
        # compatibility with the Old Agent we will get an xmlrpc request
        # from the analyzer when the analysis has finished. Now xmlrpc being
        # xmlrpc we're getting text/xml as content-type which cgi does not
        # handle. This check detects when there is no available data rather
        # than getting a hard exception trying to do so.
        if form.list:
            for key in form.keys():
                value = form[key]
                if value.filename:
                    request.files[key] = value.file
                else:
                    request.form[key] = value.value.decode("utf8")

        if "client_ip" not in state or request.client_ip == state["client_ip"]:
            self.httpd.handle(self)

class MiniHTTPServer(object):
    def __init__(self):
        self.handler = MiniHTTPRequestHandler

        # Reference back to the server.
        self.handler.httpd = self

        self.routes = {
            "GET": [],
            "POST": [],
        }

    def run(self, host="0.0.0.0", port=8000):
        self.s = SocketServer.TCPServer((host, port), self.handler)
        self.s.allow_reuse_address = True
        self.s.serve_forever()

    def route(self, path, methods=["GET"]):
        def register(fn):
            for method in methods:
                self.routes[method].append((re.compile(path + "$"), fn))
            return fn
        return register

    def handle(self, obj):
        for route, fn in self.routes[obj.command]:
            if route.match(obj.path):
                ret = fn()
                break
        else:
            ret = json_error(404, message="Route not found")

        ret.init()
        obj.send_response(ret.status_code)
        ret.headers(obj)
        obj.end_headers()

        if isinstance(ret, jsonify):
            obj.wfile.write(ret.json())
        elif isinstance(ret, send_file):
            ret.write(obj.wfile)

    def shutdown(self):
        # BaseServer also features a .shutdown() method, but you can't use
        # that from the same thread as that will deadlock the whole thing.
        self.s._BaseServer__shutdown_request = True

class jsonify(object):
    """Wrapper that represents Flask.jsonify functionality."""
    def __init__(self, **kwargs):
        self.status_code = 200
        self.values = kwargs

    def init(self):
        pass

    def json(self):
        return json.dumps(self.values)

    def headers(self, obj):
        pass

class send_file(object):
    """Wrapper that represents Flask.send_file functionality."""
    def __init__(self, path):
        self.path = path
        self.status_code = 200

    def init(self):
        if not os.path.isfile(self.path):
            self.status_code = 404
            self.length = 0
        else:
            self.length = os.path.getsize(self.path)

    def write(self, sock):
        if not self.length:
            return

        with open(self.path, "rb") as f:
            while True:
                buf = f.read(1024 * 1024)
                if not buf:
                    break

                sock.write(buf)

    def headers(self, obj):
        obj.send_header("Content-Length", self.length)

class request(object):
    form = {}
    files = {}
    client_ip = None
    client_port = None
    environ = {
        "werkzeug.server.shutdown": lambda: app.shutdown(),
    }

app = MiniHTTPServer()
state = {}

def json_error(error_code, message):
    r = jsonify(message=message, error_code=error_code)
    r.status_code = error_code
    return r

def json_exception(message):
    r = jsonify(message=message, error_code=500,
                traceback=traceback.format_exc())
    r.status_code = 500
    return r

def json_success(message, **kwargs):
    return jsonify(message=message, **kwargs)

@app.route("/")
def get_index():
    return json_success(
        "Cuckoo Agent!", version=AGENT_VERSION, features=AGENT_FEATURES
    )

@app.route("/status")
def get_status():
    return json_success("Analysis status",
                        status=state.get("status"),
                        description=state.get("description"))

@app.route("/status", methods=["POST"])
def put_status():
    if "status" not in request.form:
        return json_error(400, "No status has been provided")

    state["status"] = request.form["status"]
    state["description"] = request.form.get("description")
    return json_success("Analysis status updated")

@app.route("/logs")
def get_logs():
    return json_success(
        "Agent logs",
        stdout=sys.stdout.getvalue(),
        stderr=sys.stderr.getvalue()
    )

@app.route("/system")
def get_system():
    return json_success("System", system=platform.system())

@app.route("/environ")
def get_environ():
    return json_success("Environment variables", environ=dict(os.environ))

@app.route("/path")
def get_path():
    return json_success("Agent path", filepath=os.path.abspath(__file__))

@app.route("/mkdir", methods=["POST"])
def do_mkdir():
    if "dirpath" not in request.form:
        return json_error(400, "No dirpath has been provided")

    mode = int(request.form.get("mode", 0777))

    try:
        os.makedirs(request.form["dirpath"], mode=mode)
    except:
        return json_exception("Error creating directory")

    return json_success("Successfully created directory")

@app.route("/mktemp", methods=["GET", "POST"])
def do_mktemp():
    suffix = request.form.get("suffix", "")
    prefix = request.form.get("prefix", "tmp")
    dirpath = request.form.get("dirpath")

    fd, filepath = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=dirpath)
    os.close(fd)

    return json_success("Successfully created temporary file",
                        filepath=filepath)

@app.route("/mkdtemp", methods=["GET", "POST"])
def do_mkdtemp():
    suffix = request.form.get("suffix", "")
    prefix = request.form.get("prefix", "tmp")
    dirpath = request.form.get("dirpath")

    dirpath = tempfile.mkdtemp(suffix=suffix, prefix=prefix, dir=dirpath)
    return json_success("Successfully created temporary directory",
                        dirpath=dirpath)

@app.route("/store", methods=["POST"])
def do_store():
    if "filepath" not in request.form:
        return json_error(400, "No filepath has been provided")

    if "file" not in request.files:
        return json_error(400, "No file has been provided")

    try:
        with open(request.form["filepath"], "wb") as f:
            shutil.copyfileobj(request.files["file"], f, 10*1024*1024)
    except:
        return json_exception("Error storing file")

    return json_success("Successfully stored file")

@app.route("/retrieve", methods=["POST"])
def do_retrieve():
    if "filepath" not in request.form:
        return json_error(400, "No filepath has been provided")

    return send_file(request.form["filepath"])

@app.route("/extract", methods=["POST"])
def do_extract():
    if "dirpath" not in request.form:
        return json_error(400, "No dirpath has been provided")

    if "zipfile" not in request.files:
        return json_error(400, "No zip file has been provided")

    try:
        with zipfile.ZipFile(request.files["zipfile"], "r") as archive:
            archive.extractall(request.form["dirpath"])
    except:
        return json_exception("Error extracting zip file")

    return json_success("Successfully extracted zip file")

@app.route("/remove", methods=["POST"])
def do_remove():
    if "path" not in request.form:
        return json_error(400, "No path has been provided")

    try:
        if os.path.isdir(request.form["path"]):
            # Mark all files as readable so they can be deleted.
            for dirpath, _, filenames in os.walk(request.form["path"]):
                for filename in filenames:
                    os.chmod(os.path.join(dirpath, filename), stat.S_IWRITE)

            shutil.rmtree(request.form["path"])
            message = "Successfully deleted directory"
        elif os.path.isfile(request.form["path"]):
            os.chmod(request.form["path"], stat.S_IWRITE)
            os.remove(request.form["path"])
            message = "Successfully deleted file"
        else:
            return json_error(404, "Path provided does not exist")
    except:
        return json_exception("Error removing file or directory")

    return json_success(message)

@app.route("/execute", methods=["POST"])
def do_execute():
    if "command" not in request.form:
        return json_error(400, "No command has been provided")

    # Execute the command asynchronously? As a shell command?
    async = "async" in request.form
    shell = "shell" in request.form

    cwd = request.form.get("cwd")
    stdout = stderr = None

    try:
        if async:
            subprocess.Popen(request.form["command"], shell=shell, cwd=cwd)
        else:
            p = subprocess.Popen(
                request.form["command"], shell=shell, cwd=cwd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, stderr = p.communicate()
    except:
        return json_exception("Error executing command")

    return json_success("Successfully executed command",
                        stdout=stdout, stderr=stderr)

@app.route("/execpy", methods=["POST"])
def do_execpy():
    if "filepath" not in request.form:
        return json_error(400, "No Python file has been provided")

    # Execute the command asynchronously? As a shell command?
    async = "async" in request.form

    cwd = request.form.get("cwd")
    stdout = stderr = None

    args = [
        sys.executable,
        request.form["filepath"],
    ]

    try:
        if async:
            subprocess.Popen(args, cwd=cwd)
        else:
            p = subprocess.Popen(args, cwd=cwd,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
    except:
        return json_exception("Error executing command")

    return json_success("Successfully executed command",
                        stdout=stdout, stderr=stderr)

@app.route("/pinning")
def do_pinning():
    if "client_ip" in state:
        return json_error(500, "Agent has already been pinned to an IP!")

    state["client_ip"] = request.client_ip
    return json_success("Successfully pinned Agent",
                        client_ip=request.client_ip)

@app.route("/kill")
def do_kill():
    shutdown = request.environ.get("werkzeug.server.shutdown")
    if shutdown is None:
        return json_error(500, "Not running with the Werkzeug server")

    shutdown()
    return json_success("Quit the Cuckoo Agent")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default="0.0.0.0")
    parser.add_argument("port", nargs="?", default="8000")
    args = parser.parse_args()

    app.run(host=args.host, port=int(args.port))
