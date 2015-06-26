import flask
import os
import sys

from distributed.db import db, AlembicVersion
from distributed.views import blueprints

def create_app(database_connection):
    app = flask.Flask("Distributed Cuckoo")
    app.config["SQLALCHEMY_DATABASE_URI"] = database_connection
    app.config["SECRET_KEY"] = os.urandom(32)

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
            sys.exit("Your database is not up-to-date. Please upgrade it "
                     "using alembic (run `alembic upgrade head`).")

    return app
