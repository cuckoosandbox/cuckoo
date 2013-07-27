=============
Web interface
=============

Cuckoo provides a web interface utility that you can use to submit files to
be analyzed and view analysis reports.

Configuration
=============

The web interface pulls data from Mongo database so have Mongo reporting module
enabled in reports.conf is mandatory for web interface usage.

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
