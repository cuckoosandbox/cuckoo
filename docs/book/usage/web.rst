=============
Web interface
=============

Cuckoo provides a full-fledged web interface in the form of a Django
application. This interface will allow you to submit files, browse through the
reports, and search across all the analysis results.

Configuration
=============

The web interface pulls data from a Mongo database, so having the Mongo
reporting module enabled in ``reporting.conf`` is mandatory for the Web
Interface to function. If that's not the case, the Web Interface won't be able
to start and will instead raise an exception.

Some additional configuration options exist in the
``$CWD/web/local_settings.py`` configuration file.

.. literalinclude:: ../../../cuckoo/data/web/local_settings.py
    :language: python

It is recommended to keep the ``DEBUG`` variable at ``False`` in production
setups and to configure at least one ``ADMIN`` entry to enable error
notification by email.

.. versionchanged:: 2.0.0
   The default maximum upload size has been bumped from 25 MB to 10 GB so that
   virtually any file should be accepted.

Starting the Web Interface
==========================

In order to start the web interface, you can simply run the following command
from the ``web/`` directory::

    $ cuckoo web runserver

If you want to configure the web interface as listening for any IP on a
specified port, you can start it with the following command (replace PORT
with the desired port number)::

    $ cuckoo web runserver 0.0.0.0:PORT

Or directly without the ``runserver`` part as follows while also specifying
the host to listen on::

    $ cuckoo web -H 0

.. _web_deployment:

Web Deployment
--------------

While the default method of starting the Web Interface server works fine for
many cases, some users may wish to deploy the server in a more robust manner.
This can be done by exposing the Web Interface as a WSGI application to a web
server. This section shows a simple example of deploying the Web Interface via
`uWSGI`_ and `nginx`_. These instructions are written with Ubuntu GNU/Linux in
mind, but may be adapted to other platforms.

This solution requires ``uWSGI``, the ``uWSGI Python plugin``, and ``nginx``.
All are available as packages::

    $ sudo apt-get install uwsgi uwsgi-plugin-python nginx

uWSGI setup
^^^^^^^^^^^

First, use uWSGI to run the Web Interface server as an application.

To begin, create a uWSGI configuration file at
``/etc/uwsgi/apps-available/cuckoo-web.ini`` that contains the actual
configuration as reported by the ``cuckoo web --uwsgi`` command, e.g.::

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
    env = CUCKOO_APP=web
    env = CUCKOO_CWD=/home/..somepath..

This configuration inherits a number of settings from the distribution's
default uWSGI configuration and imports ``cuckoo.web.web.wsgi`` from the
Cuckoo package to do the actual work. In this example we installed Cuckoo in a
virtualenv located at ``/home/cuckoo/cuckoo``. If Cuckoo is installed globally
no virtualenv option is required (and ``cuckoo web --uwsgi`` would not report
one).

Enable the app configuration and start the server.

.. code-block:: bash

    $ sudo ln -s /etc/uwsgi/apps-available/cuckoo-web.ini /etc/uwsgi/apps-enabled/
    $ sudo service uwsgi start cuckoo-web    # or reload, if already running

.. note::

   Logs for the application may be found in the standard directory for distribution
   app instances, i.e., ``/var/log/uwsgi/app/cuckoo-web.log``.
   The UNIX socket is created in a conventional location as well,
   ``/run/uwsgi/app/cuckoo-web/socket``.

nginx setup
^^^^^^^^^^^

With the Web Interface server running in uWSGI, nginx can now be set up to run
as a web server/reverse proxy, backending HTTP requests to it.

To begin, create a nginx configuration file at
``/etc/nginx/sites-available/cuckoo-web`` that contains the actual
configuration as reported by the ``cuckoo web --nginx`` command::

    $ cuckoo web --nginx
    upstream _uwsgi_cuckoo_web {
        server unix:/run/uwsgi/app/cuckoo-web/socket;
    }

    server {
        listen localhost:8000;

        # Cuckoo Web Interface
        location / {
            client_max_body_size 1G;
            uwsgi_pass  _uwsgi_cuckoo_web;
            include     uwsgi_params;
        }
    }

Make sure that nginx can connect to the uWSGI socket by placing its user in the
**cuckoo** group::

    $ sudo adduser www-data cuckoo

Enable the server configuration and start the server.

.. code-block:: bash

    $ sudo ln -s /etc/nginx/sites-available/cuckoo-web /etc/nginx/sites-enabled/
    $ sudo service nginx start    # or reload, if already running

At this point, the Web Interface server should be available at port **8000**
on the server. Various configurations may be applied to extend this
configuration, such as to tune server performance, add authentication, or to
secure communications using HTTPS. However, we leave this as an exercise for
the user.

.. _`uWSGI`: http://uwsgi-docs.readthedocs.org/en/latest/
.. _`nginx`: http://nginx.org/
