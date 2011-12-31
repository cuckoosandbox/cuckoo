#!/usr/bin/python
# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2011  Claudio "nex" Guarnieri (nex@cuckoobox.org)
# http://www.cuckoobox.org
#
# This file is part of Cuckoo.
#
# Cuckoo is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Cuckoo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.

import os
import urlparse
from optparse import OptionParser
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

from cuckoo.core.db import CuckooDatabase

try:
    from mako.template import Template
    from mako.lookup import TemplateLookup
    IS_MAKO = True
except ImportError, why:
    IS_MAKO = False

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        lookup = TemplateLookup(directories=["cuckoo/web/"],
                                output_encoding='utf-8',
                                encoding_errors='replace')
        template = lookup.get_template("web.html")

        try:
            parts = os.path.split(self.path)
            if parts[0] == "/":
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()

                db = CuckooDatabase()
                tasks = db.completed_tasks(30)
                html = template.render(section_title="Recent Analysis", tasks=tasks)
                self.wfile.write(html)
                return
            elif parts[0] == "/analysis":
                analysis_id = parts[1].strip()

                if not analysis_id.isdigit():
                    self.send_error(404)
                    return

                analysis_path = "analysis/%s/reports/report.html" % analysis_id

                if os.path.exists(analysis_path):
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(open(analysis_path, "rb").read())
                    return
                else:
                    self.send_error(404)
                    return
            elif parts[0] == "/search":
                md5 = parts[1].strip()

                if not md5.isalnum() or len(md5) != 32:
                    self.send_error(404)
                    return

                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()

                db = CuckooDatabase()
                tasks = db.search_tasks(md5)
                html = template.render(section_title="Search results for: %s" % md5, tasks=tasks)
                self.wfile.write(html)
                return
            else:
                self.send_error(404)
                return
        except Exception, why:
            print why
            self.send_error(404)
            return

    def do_POST(self):
        content_len = int(self.headers.getheader("Content-length"))
        postvars = urlparse.parse_qs(self.rfile.read(content_len))

        md5 = postvars["md5"][0].strip()

        if not md5.isalnum() or len(md5) != 32:
            print "invalid"
            self.send_error(404)
            return

        self.send_response(302)
        self.send_header("Location", "/search/%s" % md5)
        self.end_headers()
        return

def main():
    if not IS_MAKO:
        print "ERROR: Unable to start webserver, Python Mako not installed."
        return False

    parser = OptionParser(usage="usage: %prog [options]")
    parser.add_option("-t", "--host",
                      action="store",
                      type="string",
                      dest="host",
                      default="127.0.0.1",
                      help="Specify the address to bind the server on (default 127.0.0.1)")
    parser.add_option("-p", "--port",
                      action="store",
                      type="int",
                      dest="port",
                      default=8080,
                      help="Specify the port to bind the server on (default 8080)")

    (options, args) = parser.parse_args()

    print("Starting web server on http://%s:%s" % (options.host, options.port))

    try:
        server = HTTPServer((options.host, options.port), MyHandler)
        server.serve_forever()
    except KeyboardInterrupt:
        server.socket.close()

if __name__ == "__main__":
    main()
