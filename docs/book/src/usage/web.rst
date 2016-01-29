=============
Web interface
=============

Cuckoo provides a full-fledged web interface in the form of a Django application.
This interface will allow you to submit files, browse through the reports as well
as search across all the analysis results.

Configuration
=============

The web interface pulls data from a Mongo database, so having the Mongo reporting
module enabled in ``reporting.conf`` is mandatory for this interface.
If that's not the case, the application won't start and it will raise an exception.

The interface can be configured by editing ``local_settings.py`` under ``web/web/``::

    # If you want to customize your cuckoo path set it here.
    # CUCKOO_PATH = "/where/cuckoo/is/placed/"

    # Maximum upload size.
    MAX_UPLOAD_SIZE = 26214400

    # Override default secret key stored in secret_key.py
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

Usage
=====

In order to start the web interface, you can simply run the following command
from the ``web/`` directory::

    $ python manage.py runserver

If you want to configure the web interface as listening for any IP on a
specified port, you can start it with the following command (replace PORT
with the desired port number)::

    $ python manage.py runserver 0.0.0.0:PORT

You can serve Cuckoo's web interface using WSGI interface with common web servers:
Apache, Nginx, Unicorn and so on.
Please refer both to the documentation of the web server of your choice as well as `Django documentation`_.

.. _`Django documentation`: https://docs.djangoproject.com/
