#!/usr/bin/env python
# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import urllib2
import argparse
import json
import os
import time
import mimetools
import mimetypes
import itertools
from datetime import datetime
import logging

try:
    import socks
    HAVE_SOCKS = True
except ImportError:
    HAVE_SOCKS = False


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


class Dist_connect():
    """ Connect to distributed REST API
    """

    def __init__(self, url, resdir="results", proxy=None,
                 proxy_port=8080, logfile="cuckooinator.log"):
        """
        @param url The url (host+port) of the cuckoo server
        @param resdir: Result dir
        @param proxy: socks proxy ip
        @param proxy_port: Socks proxy port
        @param logfile: File to log into
        """
        self.logger = logging.getLogger("Cuckooinator")
        hdlr = logging.FileHandler(logfile)
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        hdlr.setFormatter(formatter)
        self.logger.addHandler(hdlr)
        self.logger.setLevel(logging.INFO)
        self.logger.info("Started logging")

        self.url = url
        self.resdir = resdir
        if proxy:
            if HAVE_SOCKS:
                print ("Setting proxy %s %s " % (proxy, proxy_port))
                self.logger.info("Setting proxy %s %s " % (proxy, proxy_port))
                socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxy, proxy_port)
                socks.wrapmodule(urllib2)
            else:
                self.logger.error("Proxy library missing")

    def __request(self, request, convert=True):
        """ Send a request to the server

        @param request The request to send to the Server
        @param convert Convert the results from json to a dict
        """

        req = urllib2.urlopen(request, timeout=60)
        if convert:
            res = json.loads(req.read())
        else:
            res = req.read()
        return res

    def get_features(self):
        """ Get Cuckoo features """
        request = "%s/get_features" % (self.url)
        return self.__request(request)

    def get_state(self, machine_id, task_id):
        """ Get machine state
        @param machine_id: Id of the machine
        @param task_id: Id of the task
        """
        request = "%s/get_state/%s/%s" % (self.url, machine_id, task_id)
        try:
            res = self.__request(request)
        except:
            res = None
        return res

    def get_result(self, machine_id, task_id, filename, tformat="json"):
        """ Get results

        @param machine_id: Id of the machine
        @param task_id: Id of the task
        @param filename: base filename for the result file
        @param tformat: result format to fetch
        """
        extlist = {"all": "_all.tar.bz2",
                   "json": "_json_report.json",
                   "html": "_html_report.html",
                   "dropped": "_dropped.tar.bz2"}
        request = "%s/get_result/%s/%s/%s" % (self.url,
                                              str(machine_id),
                                              str(task_id),
                                              tformat)
        rfile = os.path.join(self.resdir,
                             os.path.basename(filename) +
                             extlist[tformat])
        with open(rfile, "wb") as fh:
            try:
                data = self.__request(request, convert=False)
                fh.write(data)
            except:
                pass
        return rfile

    def analyse_file(self, filename, c_ver="0.6", platform="windows",
                     tool="vanilla", priority=1):
        """ Send a file to analysis

        @param filename: The file to send for scanning
        @param c_ver: The cuckoo version to use
        @param platform: The platform to use. "windows"
        @param tool: The tool to use. "vanilla" for Cuckoo default,
            "volatility" for volatility
        @param priority: The priority to process that file with
        """
        form = MultiPartForm()

        form.add_field("cuckooversion", str(c_ver))
        form.add_field("platform", str(platform))
        form.add_field("tool", str(tool))
        form.add_field("priority", str(priority))

        form.add_file_content('file', filename,
                              open(filename, "rb").read())
        # Build the request
        request = urllib2.Request(self.url + '/analyse_file')
        request.add_header('User-agent', 'Cuckooinator')
        body = str(form)
        request.add_header('Content-type', form.get_content_type())
        request.add_header('Content-length', len(body))
        request.add_data(body)

        return self.__request(request)

    def scan(self, filename):
        """ Scan one file

        @param filename: Send a file to scanning
        """
        #self.logger.info("Before sending file: %s" % (filename))
        res = self.analyse_file(filename)
        res["filename"] = filename
        if res["error"]:
            self.logger.error("Error scanning file: %s %s " %
                              (filename, res["error_text"]))
        else:
            self.logger.info("Scanning file: %s" % (filename))
        return res

    def getem(self, scan, packages=["dropped"], timeout=0):
        """ Get results

        @param scan: scan information to identify the file to get
        @param packages: a list of result-types (dropped, json, html, ...)
        @param timeout: timeout for this result-fetch
        """
        def fetchit(machine_id, task_id, filename, packages):
            for i in packages:
                self.get_result(machine_id, task_id, filename, i)
            return True
        self.logger.info("Want results for %s/%s: %s" % (scan["machine_id"],
                                                         scan["task_id"],
                                                         scan["filename"]))

        # Waiting for results
        start = datetime.now()
        while True:
            res = self.get_state(scan["machine_id"], scan["task_id"])
            if res is None or res["error"]:
                self.logger.error("ERROR, malformated return")
                break
            elif res["finished"]:
                if fetchit(scan["machine_id"], scan["task_id"],
                           scan["filename"], packages):
                    self.logger.info("Fetched results for %s/%s: %s" %
                                     (scan["machine_id"],
                                      scan["task_id"],
                                      scan["filename"]))
                    break
            elif res["analysis_error"]:
                self.logger.error("Failed, Analysis Error: %s in %s/%s: %s" %
                                  (res["error_text"], scan["machine_id"],
                                   scan["task_id"], scan["filename"]))
                break
            now = datetime.now()
            diff = now - start
            if timeout > 0 and diff.seconds > timeout:
                self.logger.error("Timeout hit. Ignoring this sample:" +
                                  "%s/%s: %s" % (scan["machine_id"],
                                                 scan["task_id"],
                                                 scan["filename"]))
                break
            time.sleep(5)

    def process(self, args):
        """ Accept a path, scan this recursively and get the results

        @param args: Arguments from commandline
        """
        def allFiles(root):
            """ Recursive processing
            """
            if os.path.isfile(root):
                yield root
            for path, subdirs, files in os.walk(root):
                for name in files:
                    yield os.path.join(path, name)

        results = []
        for afile in allFiles(args.file):
            a = self.scan(afile)
            if not a["error"]:
                results.append(a)

        total = str(len(results))
        print "submitted %s samples" % total
        self.logger.info("Submission done. Number of samples: %s" % total)

        # First sample does have an extreme timeout
        timeout = args.master_timeout

        count = 0
        for ares in results:
            self.getem(ares, ps, timeout)
            timeout = args.sub_timeout
            count += 1
            print "Done: %s/%s" % (str(count), total)
        self.logger.info("Finished")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=
                                     "Scanning one file with Cuckoo")
    parser.add_argument("--url",
                        help="The cuckoo url (http://..., including port)",
                        default="http://localhost:8080")
    parser.add_argument("--resdir", help="Result directory",
                        default="results")
    parser.add_argument("--proxy", help="URL of socks proxy", default=None)
    parser.add_argument("--proxyport", help="Port of socks proxy",
                        type=int, default=8080)
    parser.add_argument("--packages",
                        help="Result package types. all, json, dropped, html",
                        default="dropped")
    parser.add_argument("--logfile", help="Logfile to store the results",
                        default="cuckooinator.log")
    parser.add_argument("file",
                        help="File or path to test with. " +
                        "Paths will be handled recursively")
    parser.add_argument("--master_timeout",
                        help="Timeout till analysis must start and first" +
                        " result is returned. n seconds. 0 is off",
                        type=int, default=60 * 60 * 3)
    parser.add_argument("--sub-timeout",
                        help="Timeout for every additional result." +
                        " In seconds, 0 is off.",
                        type=int, default=240)

    args = parser.parse_args()
    ps = args.packages.split(",")
    dc = Dist_connect(args.url, args.resdir,
                      args.proxy, args.proxyport, logfile=args.logfile)
    dc.process(args)
