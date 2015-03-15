#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import ConfigParser
import logging
import os.path
import sys

from flask import Flask

from lib.db import db
from lib.scheduler import SchedulerThread
from views.api import blueprint as ApiBlueprint

log = logging.getLogger(__name__)

def create_app(database_connection):
    app = Flask("Distributed Cuckoo")
    app.config["SQLALCHEMY_DATABASE_URI"] = database_connection
    app.config["SECRET_KEY"] = os.urandom(32)

    app.register_blueprint(ApiBlueprint, url_prefix="/api")

    db.init_app(app)
    with app.app_context():
        db.create_all()

    return app

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("host", nargs="?", default="127.0.0.1", help="Host to listen on")
    p.add_argument("port", nargs="?", type=int, default=9003, help="Port to listen on")
    p.add_argument("-s", "--settings", type=str, help="Settings file.")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = p.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    log = logging.getLogger("cuckoo.distributed")

    if not args.settings:
        dirpath = os.path.abspath(os.path.dirname(__file__))
        conf_path = os.path.join(dirpath, "..", "conf", "distributed.conf")
        args.settings = conf_path

    s = ConfigParser.ConfigParser()
    s.read(args.settings)

    if not s.get("distributed", "database"):
        sys.exit("Please configure a database connection.")

    app = create_app(database_connection=s.get("distributed", "database"))

    report_formats = []
    for report_format in s.get("distributed", "report_formats").split(","):
        report_formats.append(report_format.strip())

    if not report_formats:
        sys.exit("Please configure one or more reporting formats.")

    app.config["REPORT_FORMATS"] = report_formats

    app.config["SAMPLES_DIRECTORY"] = \
        s.get("distributed", "samples_directory")

    if not app.config["SAMPLES_DIRECTORY"]:
        sys.exit("Please configure a samples directory path.")

    if not os.path.isdir(app.config["SAMPLES_DIRECTORY"]):
        os.makedirs(app.config["SAMPLES_DIRECTORY"])

    app.config["REPORTS_DIRECTORY"] = \
        s.get("distributed", "reports_directory")

    if not app.config["REPORTS_DIRECTORY"]:
        sys.exit("Please configure a reports directory path.")

    if not os.path.isdir(app.config["REPORTS_DIRECTORY"]):
        os.makedirs(app.config["REPORTS_DIRECTORY"])

    app.config["RUNNING"] = True
    app.config["STATUSES"] = {}
    app.config["VERBOSE"] = args.verbose
    app.config["WORKER_PROCESSES"] = \
        s.getint("distributed", "worker_processes")
    app.config["UPTIME_LOGFILE"] = s.get("distributed", "uptime_logfile")
    app.config["INTERVAL"] = s.getint("distributed", "interval")
    app.config["BATCH_SIZE"] = s.getint("distributed", "batch_size")

    t = SchedulerThread(app)
    t.daemon = True
    t.start()

    app.run(host=args.host, port=args.port)
