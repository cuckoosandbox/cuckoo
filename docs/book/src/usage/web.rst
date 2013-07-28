=============
Web interface
=============

Cuckoo provides a web interface utility that you can use to submit files to
be analyzed and view analysis reports.

Configuration
=============

The web interface pulls data from Mongo database so have Mongo reporting module
enabled in reports.conf is mandatory for web interface usage.

Web interface settings can be configured edititing *local_settings.py* in web folder::

    # If you want to customize your cuckoo path set it here.
    # CUCKOO_PATH = "/where/cuckoo/is/placed/"

    # If you want to customize your cuckoo temporary upload path set it here.
    # CUCKOO_FILE_UPLOAD_TEMP_DIR = "/where/web/tmp/is/placed/"

    # Maximum upload size.
    MAX_UPLOAD_SIZE = 26214400

    # Make this unique, and don't share it with anybody.
    SECRET_KEY = 'z=#dz9%bce-_%l3s!$uldoq^!mb^kl*k%6p%t2ycn#(ug+6#7o'

    # Local time zone for this installation. Choices can be found here:
    # http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
    # although not all choices may be available on all operating systems.
    # On Unix systems, a value of None will cause Django to use the same
    # timezone as the operating system.
    # If running in a Windows environment this must be set to the same as your
    # system time zone.
    TIME_ZONE = 'America/Chicago'

    # Language code for this installation. All choices can be found here:
    # http://www.i18nguy.com/unicode/language-identifiers.html
    LANGUAGE_CODE = 'en-us'

    ADMINS = (
        # ('Your Name', 'your_email@example.com'),
    )

    MANAGERS = ADMINS


Usage
=====

You can find the folder at path *web* in the Cuckoo's root and you can start it running
the following command inside the *web* directory::

    $ python manage.py runserver

By default it will create a webserver on localhost and port 8000. Open your
browser at *http://localhost:8000* and it will prompt you a simple form that
allows you to upload a file, specify some options (with the same format as
the *submit.py* utility) and submit it.

If you want to configure the web interface as listening for any IPs on a
specified port, you run start it with the following command (replace PORT
with the number of your desired port)::

    $ python manage.py runserver 0.0.0.0:PORT

You can serve Cuckoo's web interface using WSGI interface with common web servers:
Apache, Nginx, Unicorn and so on.
Please refer to your web server documentation on how to deploy WSGI applications.