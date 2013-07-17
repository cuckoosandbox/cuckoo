#!/usr/bin/env python
# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from urllib2 import urlopen, HTTPError, Request, URLError
import json
import urllib
import itertools
import mimetools
import mimetypes
import ConfigParser
from random import choice
import os
import time
import logging
from bottle import Bottle, run, response, request
from random import choice


def jsonize(data):
    """Converts data dict to JSON.
    @param data: data dict
    @return: JSON formatted data
    """
    response.content_type = "application/json; charset=UTF-8"
    return json.dumps(data, sort_keys=False, indent=4)


class ComExcept(Exception):
    """ Communcation Exception
    """
    pass


class MultiPartForm(object):
    """Accumulate the data to be used when posting a form.

    From http://pymotw.com/2/urllib2/

    """

    def __init__(self):
        self.form_fields = []
        self.files = []
        self.boundary = mimetools.choose_boundary()
        return

    def get_content_type(self):
        return "multipart/form-data; boundary=%s" % self.boundary

    def add_field(self, name, value):
        """Add a simple field to the form data."""
        self.form_fields.append((name, value))
        return

    def add_file(self, fieldname, filename, fileHandle, mimetype=None):
        """Add a file to be uploaded."""
        body = fileHandle.read()
        if mimetype is None:
            mimetype = mimetypes.guess_type(filename)[0] or\
                "application/octet-stream"
        self.files.append((fieldname, filename, mimetype, body))
        return

    def add_file_content(self, fieldname, filename,
                         fileContent, mimetype=None):
        """Add a file to be uploaded."""
        body = fileContent
        if mimetype is None:
            mimetype = mimetypes.guess_type(filename)[0] or\
                "application/octet-stream"
        self.files.append((fieldname, filename, mimetype, body))
        return

    def __str__(self):
        """Return a string representing the form data,
            including attached files.

        """
        # Build a list of lists, each containing "lines" of the
        # request.  Each part is separated by a boundary string.
        # Once the list is built, return a string where each
        # line is separated by '\r\n'.
        parts = []
        part_boundary = "--" + self.boundary

        # Add the form fields
        parts.extend(
            [part_boundary,
             "Content-Disposition: form-data; name=\"%s\"" % name,
             "",
             value]
            for name, value in self.form_fields)

        # Add the files to upload
        parts.extend(
            [part_boundary,
             "Content-Disposition: file; name=\"%s\"; filename=\"%s\"" %
             (field_name, filename),
             "Content-Type: %s" % content_type,
             "",
             body]
            for field_name, filename, content_type, body in self.files)

        # Flatten the list and add closing boundary marker,
        # then return CR+LF separated data
        flattened = list(itertools.chain(*parts))
        flattened.append("--" + self.boundary + "--")
        flattened.append("")
        return "\r\n".join(flattened)


class CuckooConnect():
    def __init__(self, url, logger):
        """
        @param url: The url (host+port) of the cuckoo server
        @param logger: The logger
        """

        self.url = url
        self.logger = logger

    def __request(self, request, convert=True):
        """ Send a request to the server

        @param request The request to send to the Server
        @param convert Convert the results from json to a dict
        """

        try:
            req = urlopen(request, timeout=60)
            if convert:
                res = json.loads(req.read())
            else:
                res = req.read()
            return res
        except:
            try:
                self.logger.warn("Exception on request %s" %
                                 request.get_full_url())
            except AttributeError:
                self.logger.warn("Exception on request %s" % request)
            raise ComExcept()

    def tasks_create_file(self, filename, fdata=None, options={}):
        """ Send a file to the Cuckoo Server

        curl -F file=@/path/to/file http://localhost:8090/tasks/create/file

        @param filename: File to analyze
        @param fdata: The file handle to the file (if not available,
            it will read the file)
        @param options: Additional options for this task. Can be:
            package Package to use
            timeout Timeout to set
            options Additional options
            machine Machine to use
            platform Platform to use
            custom Custom string to pass through the analysis process
            memory Do memory dump
            enforce_timeout enforce the execution for the full timeout value
        """

        form = MultiPartForm()

        optional = ["package", "timeout", "options", "machine",
                    "platform", "custom", "memory", "enforce_timeout"]

        for o in optional:
            if o in options:
                form.add_field(o, str(options[o]))
        if not fdata:
            form.add_file_content("file", filename,
                                  open(filename, "rb"))
        else:
            form.add_file("file", filename, fdata)
        # Build the request
        request = Request(self.url + "/tasks/create/file")
        request.add_header("User-agent", "Cuckoo dist")
        body = str(form)
        request.add_header("Content-type", form.get_content_type())
        request.add_header("Content-length", len(body))
        request.add_data(body)

        return self.__request(request)

    def tasks_create_url(self, url, options={}):
        """ Send a url to the Cuckoo Server

        curl -F url="http://www.malicious.site"
            http://localhost:8090/tasks/create/url

        @param url URL to analyze
        @param options Additional options for this task. Can be:
            package Package to use
            timeout Timeout to set
            options Additional options
            machine Machine to use
            platform Platform to use
            custom Custom string to pass through the analysis process
            memory Do memory dump
            enforce_timeout enforce the execution for the full timeout value
        """

        form = MultiPartForm()

        optional = ["package", "timeout", "options", "machine",
                    "platform", "custom", "memory", "enforce_timeout"]

        for o in optional:
            if o in options:
                form.add_field(o, options(o))

        form.add_field("url", url)

        # Build the request
        request = Request(self.url + "/tasks/create/url")
        request.add_header("User-agent", "Cuckoo dist")
        body = str(form)
        request.add_header("Content-type", form.get_content_type())
        request.add_header("Content-length", len(body))
        request.add_data(body)

        return self.__request(request)

    def tasks_list(self, limit=None):
        """ List task

        curl http://localhost:8090/tasks/list

        @param limit: Limit the number of tasks returned
        """
        if limit:
            pass
            request = "%s/tasks/list/%s" % (self.url, str(limit))
        else:
            request = "%s/tasks/list" % (self.url)
        return self.__request(request)

    def tasks_view(self, taskid):
        """ View information about a specific task

        curl http://localhost:8090/tasks/view/1

        @param taskid: Task id to view
        """

        request = "%s/tasks/view/%s" % (self.url, str(taskid))
        return self.__request(request)

    def tasks_delete(self, taskid):
        """ Delete a task

        curl http://localhost:8090/tasks/delete/1

        @param taskid: Task id to delete
        """
        request = "%s/tasks/delete/%s" % (self.url, str(taskid))
        return self.__request(request)

    def tasks_report(self, taskid, format="json"):
        """ Get the results for the given task id

        @param taskid: Taskid of the task to request
        @param format: Format of the report to request
        """
        request = "%s/tasks/report/%s/%s" % (self.url, str(taskid), format)
        return self.__request(request, convert=False)

    def files_view(self, identifier, id):
        """ View file data

        @param identifier: "md5","sha256","id"
        @param id: to search for
        """

        request = "%s/files/view/%s/%s" % (self.url, str(identifier), id)
        return self.__request(request)

    def files_get(self, sha256, filename):
        """ Get file data

        @param sha256: sha256 of the file to get
        @param filename: name of the file to write to
        """

        request = "%s/files/get/%s" % (self.url, str(sha256))
        try:
            req = urlopen(request, timeout=1)
            res = req.read()
            fh = open(filename, "wb")
            fh.write(res)
            fh.close()
        except:
            raise ComExcept()

    def machines_list(self):
        """ Returns the machines list
        """

        try:
            request = self.url + "/machines/list"
            res = self.__request(request)
        except ComExcept:
            res = {}
        return res

    def machines_view(self, name):
        """ Views machine details

        @param name: machine name
        """

        request = self.url + "/machines/view/" + name
        return self.__request(request)

    def machines_available(self, platform=None):
        """ List available machines

        @param platform: Platform to filter for
        """

        res = []

        ml = self.machines_list()

        if "machines" in ml:
            for m in ml["machines"]:
                if (m["status"] is None and m["locked"] is False and
                   (platform is None or platform == m["platform"])):
                    res.append(m["name"])

        return res

    def machines_all(self, platform=None):
        """ List non available machines

        @param platform: Platform to filter for
        """

        res = []

        ml = self.machines_list()

        if "machines" in ml:
            for m in ml["machines"]:
                if (platform is None or platform == m["platform"]):
                    res.append(m["name"])

        return res

    def cuckoo_status(self):
        """ Get cuckoo status """

        request = self.url + "/cuckoo/status"
        return self.__request(request)

    def task_status(self, taskid):
        """ Return the task status as string

        @param taskid: Task to get status for
        """

        return self.tasks_view(taskid)["task"]["status"]

    def is_done(self, taskid):
        """ Returns true if an analysis is done

        @param taskid: Task to get status for
        """
        # "TASK_REPORTED" for cuckoo 0.7, success for cuckoo 0.6

        if self.task_status(taskid) in ["reported"]:
            return True

    def task_status_stats(self, machine=None):
        """ Returns a status statistics for all tasks on this Cuckoo

        @param machine: optional machine to create the statistics for
        """

        res = {}
        tasks = self.tasks_list()
        for t in tasks["tasks"]:
            if machine is None or ("label" in t["guest"] and
                                   str(t["guest"]["label"]) == machine):
                if str(t["status"]) in res:
                    res[str(t["status"])] += 1
                else:
                    res[str(t["status"])] = 1
        return res


class RESTServer():
    """ A http rest server that receives requests and
        dispatches them to Cuckoos
    """

    def __init__(self, host="localhost", port="8080",
                 inifile="dist.ini", debug=False):
        """
        @param host: The host to run the server on
        @param port: The port for the server
        @param inifile: The configuration file
        @param debug: Toggling some debug features
        """

        self.host = host
        self.port = port
        self.debug = debug
        self.inifile = inifile
        self.connections = {}  # Internal connection data
        self.machines = None   # List of machine data
        self.logger = logging.getLogger("Distributed Cuckoo REST")
        self._app = Bottle()
        self.load_conf()
        self._route()
        self.__connectit__()

    def load_conf(self):
        """ Read configuration file
        """
        config = ConfigParser.ConfigParser()
        config.read(self.inifile)
        self.logfile = config.get("Basic", "logfile")
        hdlr = logging.FileHandler(self.logfile)
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        hdlr.setFormatter(formatter)
        self.logger.addHandler(hdlr)
        self.logger.setLevel(logging.INFO)
        self.logger.info("Started logging")

        self.machines = []

        def get_vms(connection):
            """ Return all vms on a system and the configurations

            @param connection: Connection to the cuckoo
            """
            return connection.machines_list()

        def get_machine(mname):
            """ Read machine part of the config

            @param mname: machine section name
            """
            res = {}

            url = config.get(mname, "url")
            res = {"url": url,
                    "con": CuckooConnect(url,
                    self.logger)}

            state = res["con"].cuckoo_status()
            
            res["cuckoo_version"] = state["version"]
            res["stable"] = True
            if state["version"].lower().endswith("dev"):
                res["stable"] = False
            res["id"] = state["hostname"]

            self.connections[res["id"]] = res

            res["vms"] = get_vms(res["con"])["machines"]
            
            print res
            return res

        for t in config.get("Rest", "machines_active").split(","):
            self.machines.append(get_machine(t.strip()))
        self.logger.info("Finished loading INI")

    def _route(self):
        """ Create routes
        """
        self._app.route("/get_state/<machine_id>/<task_id>",
                        method="GET", callback=self.get_state)
        self._app.route("/get_result/<machine_id>/<task_id>",
                        callback=self.get_result)
        self._app.route("/get_result/<machine_id>/<task_id>/<report_format>",
                        callback=self.get_result)
        self._app.route("/get_features", callback=self.get_features)
        self._app.route("/analyse_file", method="POST",
                        callback=self.analyse_file)
        if self.debug:
            self._app.route("/", method="GET", callback=self.info)
            self._app.route("/upload_gui", callback=self.upload_gui)

    def __connectit__(self):
        """ Connect everything and start server
        """
        run(app=self._app, host=self.host, port=self.port)

    def get_state(self, machine_id, task_id):
        """ Get the analysis state

        @param machine_id: machine id to get state from
        @apram task_id: task id to get state from
        """
        res = {"finished": False,
               "started": False,
               "analysis_error": False,
               "error": False,
               "error_text": ""}

        try:
            task = self.connections[machine_id]["con"].tasks_view(task_id)["task"]
            if task["status"] in ["reported"]:
                res["finished"] = True
                self.logger.info("Cuckoo finished %s/%s" %
                              (str(machine_id), str(task_id)))
            if task["status"] in ["running", "completed", "reported"]:
                res["started"] = True
            if len(task["errors"]) > 0:
                res["analysis_error"] = True
                res["error_text"] = "Cuckoo state is failure"
                self.logger.error("Cuckoo error %s/%s" %
                              (str(machine_id), str(task_id)))
        except:
            res["error"] = True
            res["error_text"] = "Error connecting to api"
            self.logger.error("Error connecting to API in get_state %s/%s" %
                              (str(machine_id), str(task_id)))
        return jsonize(res)

    def info(self):
        """ Returns basic info. For testing
        """

        return "Cuckoo distributed processing API"

    def get_result(self, machine_id, task_id, report_format="json"):
        """ Return the result

        @param machine_id: id of the machine to get reports from
        @param task_id: id of the task to get results from
        @param report_format: "json", "html", "maec",
            "metadata", "all", "dropped"
        @return: returns the buffer containing the result file
        """

        report = self.connections[machine_id]["con"].\
            tasks_report(task_id, format=report_format)

        self.logger.info("Cuckoo report %s/%s Format: %s" %
                              (str(machine_id), str(task_id), report_format))
        if report_format in ["all", "dropped"]:
            response.content_type = "application/x-tar; charset=UTF-8"

        return report

    def get_features(self):
        """ Return features available for analysis
        """
        res = {"machines": self.machines,
               "error": False,
               "error_text": ""}
        return jsonize(res)

    def get_machines(self, version, platform, tool):
        """return a list of machines with matching parameters

        @param version: Cuckoo version to filter for
        @param platform: Platform to filter for
        @param tool: Tool to filter for
        """

        res = []
        for m in self.machines:
            if m["cuckoo_version"] == version:
                pok = False
                tok = False
                for p in m["platforms"]:
                    if p["id"] == platform:
                        pok = True
                for t in m["tools"]:
                    if t["id"] == tool:
                        tok = True
                if pok and tok:
                    res.append(m["id"])
        return res

    def analyse_file(self):
        response = {"error": False,
                    "error_text": ""}

        data = request.files.file
        cuckoo_ver = request.forms.get("cuckooversion", "")
        platform = request.forms.get("platform", None)
        tool = request.forms.get("tool", "vanilla")
        priority = request.forms.get("priority", 1)

        m_pot = self.get_machines(cuckoo_ver, platform, tool)
        if len(m_pot) == 0:
            response["error"] = True
            response["error_text"] =\
                "No machine available for cv: %s, pl: %s, tool: %s" %\
                (str(cuckoo_ver), str(platform), str(tool))
            self.logger.error(
                "No machine available for cv: %s, pl: %s, tool: %s" %
                (str(cuckoo_ver), str(platform), str(tool)))
        else:
            machine_id = choice(m_pot)
            options = {"priority": priority}
            if platform:
                options["platform"] = platform.strip()
            if tool == "volatility":
                options["memory"] = True
                options["options"] = "free=True"
            try:
                print "Filename: %s Options: %s" % (data.filename, options)
                task_id =\
                    self.connections[machine_id]["con"].\
                    tasks_create_file(data.filename,
                                      fdata=data.file,
                                      options=options)
                response["task_id"] = task_id["task_id"]
                response["machine_id"] = machine_id
            except:
                response["error"] = True
                response["error_text"] = "Error while distributing job" +\
                                         " to %s file: %s" % (machine_id,
                                                              data.filename)
                self.logger.error("Error while distributing job" +
                                  " to %s file: %s" % (machine_id,
                                                       data.filename))
        return jsonize(response)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Cuckoo job distribution server")
    parser.add_argument("--config",
                        default="dist.ini", help="Configuration file to use")
    parser.add_argument("--debug", action="store_true",
                        default=False, help="Debug and training setting")
    parser.add_argument("--host",
                        default="localhost",
                        help="The host to run that server on")
    parser.add_argument("--port",
                        default="8080",
                        help="The port to run that server on")

    args = parser.parse_args()

    rs = RESTServer(args.host, args.port,
                    inifile=args.config, debug=args.debug)
