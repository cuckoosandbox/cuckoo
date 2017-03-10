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

import os
import sys

import cuckoo

from cuckoo.misc import decide_cwd

if os.environ.get("CUCKOO_APP") == "web":
    decide_cwd(exists=True)

    os.chdir(os.path.join(cuckoo.__path__[0], "web"))
    sys.path.insert(0, ".")

    cuckoo.core.database.Database().connect()

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "web.settings")

    # This application object is used by any WSGI server configured to use
    # this file. This includes Django's development server, if the
    # WSGI_APPLICATION setting points here.
    from django.core.wsgi import get_wsgi_application
    application = get_wsgi_application()

    # Apply WSGI middleware here.
    # from helloworld.wsgi import HelloWorldApplication
    # application = HelloWorldApplication(application)
