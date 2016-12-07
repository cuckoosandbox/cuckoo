# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""
WSGI config for web project.

This module contains the WSGI application used by Django's development server
and any production WSGI deployments. It should expose a module-level variable
named ``application``. Django's ``runserver`` and ``runfcgi`` commands discover
this application via the ``WSGI_APPLICATION`` setting.

Usually you will have the standard Django WSGI application here, but it also
might make sense to replace the whole Django WSGI application with a custom one
that later delegates to the Django one. For example, you could introduce WSGI
middleware here, or combine a Django application with an application of another
framework.

"""

"""

:: Correctly setting up WSGI w/ Apache2, using only HTTPS. Start here.

You can use the following command to generate SSL certs for an HTTPS setup.
# sudo openssl req -x509 -nodes -days 3650 -newkey rsa:4096 -keyout \
    /etc/apache2/ssl/cert.key -out /etc/apache2/ssl/cert.crt

The following Apache2 vhost will work plug-and-play with the above command
    assuming that cuckoo lives in /opt/cuckoo
// Begin Apache2 config for WSGI usage

<VirtualHost *:80>
        RewriteEngine On
        RewriteCond %{HTTPS} off
        RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}
</VirtualHost>

<VirtualHost *:443>

        # Remember to change paths where necessary

        SSLEngine On
        SSLCertificateFile      /etc/apache2/ssl/cert.crt
        SSLCertificateKeyFile   /etc/apache2/ssl/cert.key

        # WARNING :: I haven't looked to ensure that all libs in use are threadsafe
        #   If you have some free ram, keep your threadcount at 1; spawn processes
        #   You've been warned. Weird things may happen...
        WSGIDaemonProcess web processes=5 threads=20

        WSGIScriptAlias         /       /opt/cuckoo/web/web/wsgi.py

        <Directory /opt/cuckoo/web>
                Require         all     granted
                WSGIScriptReloading On
        </Directory>

        Alias /static /opt/cuckoo/web/static

        ErrorLog        ${APACHE_LOG_DIR}/error.log
        LogLevel        error
        CustomLog       ${APACHE_LOG_DIR}/access.log    combined

</VirtualHost>

Further, if you don't desire to have www-data be your user and group for the
cuckoo install for one reason or another, you must make two addtional changes

First, replace `WSGIDaemonProcess web processes=5 threads=20` in the config
above, with the following
    WSGIDaemonProcess web user=MyUser group=MyGroup processes=5 threads=20

    This instructs WSGI to run as a different user. THIS IS NOT RECOMMENDED
    This allows wsgi to have access to the cuckoo dir

Secondly, add the following to /etc/apache2/envvars
    export APACHE_RUN_USER=plitke
    export APACHE_RUN_GROUP=plitke

    This forces apache to run as your user/group so when it writes temp files,
      they're owned by the same user/group that wsgi is. Elsewise you get weird
      detonation failures/permission errors
    ALSO NOT RECOMMENDED

Uncomment the following lines to finalize your apache set up
If you use nginx, you can keep the chdir() commented out as you'll have
that set up elsewhere with uwsgi
"""
# These lines ensure that imports used by the WSGI daemon can be found
#import sys
#from os.path import join, dirname, abspath

# Add / and /web (relative to cuckoo-modified install location) to our path
#webdir = abspath(join(dirname(abspath(__file__)), '..'))
#sys.path.append(abspath(join(webdir, '..')))
#sys.path.append(webdir)

# Have WSGI run out of the WebDir
#from os import chdir
#chdir(webdir)

from os import environ
environ.setdefault("DJANGO_SETTINGS_MODULE", "web.settings")

# This application object is used by any WSGI server configured to use this
# file. This includes Django's development server, if the WSGI_APPLICATION
# setting points here.
from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()

