# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import flask
import os.path
import sys

from cuckoo.distributed.db import db, AlembicVersion
from cuckoo.distributed.misc import settings, init_settings
from cuckoo.distributed.views import blueprints

def create_app():
    app = flask.Flask("Distributed Cuckoo")

    init_settings()
    app.config.from_object(settings)

    for blueprint, routes in blueprints:
        for route in routes:
            app.register_blueprint(blueprint, url_prefix=route)

    db.init_app(app)
    db.create_all(app=app)

    # Check whether an alembic version is present and whether
    # we're up-to-date.
    with app.app_context():
        row = AlembicVersion.query.first()
        if not row:
            db.session.add(AlembicVersion(AlembicVersion.VERSION))
            db.session.commit()
        elif row.version_num != AlembicVersion.VERSION:
            sys.exit("Your database is not up-to-date, please upgrade it "
                     "(run `cuckoo distributed migrate`).")

    # Further check the configuration.
    if not settings.SQLALCHEMY_DATABASE_URI:
        sys.exit("Please configure a database connection.")

    if not settings.report_formats:
        sys.exit("Please configure one or more reporting formats.")

    if not settings.samples_directory or \
            not os.path.isdir(settings.samples_directory):
        sys.exit("Please configure a samples directory path.")

    if not settings.reports_directory or \
            not os.path.isdir(settings.reports_directory):
        sys.exit("Please configure a reports directory path.")

    @app.after_request
    def custom_headers(response):
        """Set some custom headers across all HTTP responses."""
        response.headers["Server"] = "Distributed Machete Server"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Pragma"] = "no-cache"
        response.headers["Cache-Control"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    return app
