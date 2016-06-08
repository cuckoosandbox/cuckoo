=============
Web interface
=============

Cuckoo provides a full-fledged web interface in the form of a Django
application. This interface will allow you to submit files, browse through the
reports as well as search across all the analysis results.

Configuration
=============

The web interface pulls data from a Mongo database, so having the Mongo
reporting module enabled in ``reporting.conf`` is mandatory for this
interface. If that's not the case, the application won't start and it will
raise an exception.

The interface can be configured by editing ``$CWD/web/local_settings.py``::

    # Copyright (C) 2010-2013 Claudio Guarnieri.
    # Copyright (C) 2014-2016 Cuckoo Foundation.
    # This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
    # See the file 'docs/LICENSE' for copying permission.

    # Maximum upload size.
    MAX_UPLOAD_SIZE = 26214400

    # Override default secret key stored in $CWD/web/.secret_key
    # Make this unique, and don't share it with anybody.
    # SECRET_KEY = "YOUR_RANDOM_KEY"

    # Language code for this installation. All choices can be found here:
    # http://www.i18nguy.com/unicode/language-identifiers.html
    LANGUAGE_CODE = "en-us"

    ADMINS = (
        # ("Your Name", "your_email@example.com"),
    )

    MANAGERS = ADMINS

    # Allow verbose debug error message in case of application fault.
    # It's strongly suggested to set it to False if you are serving the
    # web application from a web server front-end (i.e. Apache).
    DEBUG = True

    # A list of strings representing the host/domain names that this Django site
    # can serve.
    # Values in this list can be fully qualified names (e.g. 'www.example.com').
    # When DEBUG is True or when running tests, host validation is disabled; any
    # host will be accepted. Thus it's usually only necessary to set it in production.
    ALLOWED_HOSTS = ["*"]

In production deploys it is suggested to disable verbose error reporting setting
``DEBUG`` to False, it could lead to an information disclosure vulnerability. It
is also suggested to set at least one administrator email address in the
``ADMIN`` variable to enable error notification by mail.

In some cases, if you are submitting large files, it is suggested to increase
the maximum file size limit editing ``MAX_UPLOAD_SIZE``.

Starting the Web Interface
==========================

In order to start the web interface, you can simply run the following command
from the ``web/`` directory::

    $ cuckoo web runserver

If you want to configure the web interface as listening for any IP on a
specified port, you can start it with the following command (replace PORT
with the desired port number)::

    $ cuckoo web runserver 0.0.0.0:PORT

Web Deployment
--------------

While the default method of starting the Web Interface server works fine for
many cases, some users may wish to deploy the server in a robust manner. This
can be done by exposing the Web Interface as a WSGI application through a web
server. This section shows a simple example of deploying the Web Interface via
`uWSGI`_ and `Nginx`_. These instructions are written with Ubuntu GNU/Linux in
mind, but may be adapted for other platforms.

This solution requires uWSGI, the uWSGI Python plugin, and Nginx. All are
available as packages::

    $ sudo apt-get install uwsgi uwsgi-plugin-python nginx

uWSGI setup
^^^^^^^^^^^

First, use uWSGI to run the Web Interface server as an application.

To begin, create a uWSGI configuration file at
``/etc/uwsgi/apps-available/cuckoo-web.ini`` that contains the actual
configuration as reported by the ``cuckoo web --uwsgi`` command::

    $ cuckoo web --uwsgi
    [uwsgi]
    plugins = python
    virtualenv = /home/cuckoo/cuckoo
    module = cuckoo.web.web.wsgi
    uid = cuckoo
    gid = cuckoo
    static-map = /static=/home/..somepath..
    # If you're getting errors about the PYTHON_EGG_CACHE, then
    # uncomment the following line and add some path that is
    # writable from the defined user.
    # env = PYTHON_EGG_CACHE=
    env = CUCKOO_FORCE=/home/..somepath..

This configuration inherits a number of settings from the distribution's
default uWSGI configuration and imports ``cuckoo.web.web.wsgi`` from the
Cuckoo package to do the actual work. In this example we installed Cuckoo in a
virtualenv located at ``/home/cuckoo/cuckoo``. If Cuckoo is installed globally
no virtualenv option is required.

Enable the app configuration and start the server::

    $ sudo ln -s /etc/uwsgi/apps-available/cuckoo-web.ini /etc/uwsgi/apps-enabled/
    $ sudo service uwsgi start cuckoo-web    # or reload, if already running

.. note::

   Logs for the application may be found in the standard directory for distribution
   app instances, i.e.:

   ``/var/log/uwsgi/app/cuckoo-web.log``

   The UNIX socket is created in a conventional location as well:

   ``/run/uwsgi/app/cuckoo-web/socket``

Nginx setup
^^^^^^^^^^^

With the Web Interface server running in uWSGI, Nginx can now be set up to run
as a web server/reverse proxy, backending HTTP requests to it.

To begin, create a Nginx configuration file at
``/etc/nginx/sites-available/cuckoo-web`` that contains the actual
configuration as reportd by the ``cuckoo web --nginx`` command::

    $ cuckoo web --nginx
    upstream _uwsgi_cuckoo_web {
        server unix:/run/uwsgi/app/cuckoo-web/socket;
    }

    server {
        listen 8090;
        listen [::]:8090 ipv6only=on;

        # Cuckoo Web Interface
        location / {
            uwsgi_pass  _uwsgi_cuckoo_web;
            include     uwsgi_params;
        }
    }

Make sure that Nginx can connect to the uWSGI socket by placing its user in the
**cuckoo** group::

    $ sudo adduser www-data cuckoo

Enable the server configuration and start the server::

    $ sudo ln -s /etc/nginx/sites-available/cuckoo-web /etc/nginx/sites-enabled/
    $ sudo service nginx start    # or reload, if already running

At this point, the Web Interface server should be available at port **8000**
on the server. Various configurations may be applied to extend this
configuration, such as to tune server performance, add authentication, or to
secure communications using HTTPS.

.. _`uWSGI`: http://uwsgi-docs.readthedocs.org/en/latest/
.. _`Nginx`: http://nginx.org/
