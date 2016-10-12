# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import pymongo

from cuckoo.common.config import Config
from cuckoo.misc import cwd, set_cwd, _root

if os.environ.get("CUCKOO_CWD") and _root is None:
    set_cwd(os.environ.get("CUCKOO_CWD"))

cfg = Config("reporting")

# Checks if mongo reporting is enabled in Cuckoo.
if not cfg.mongodb.get("enabled"):
    raise Exception("Mongo reporting module is not enabled in cuckoo, aborting!")

# Get connection options from reporting.conf.
MONGO_HOST = cfg.mongodb.get("host", "127.0.0.1")
MONGO_PORT = cfg.mongodb.get("port", 27017)
MONGO_DB = cfg.mongodb.get("db", "cuckoo")
MONGO_USER = cfg.mongodb.get("user", None)
MONGO_PASS = cfg.mongodb.get("pass", None)

try:
    _mongo = pymongo.MongoClient(MONGO_HOST, MONGO_PORT)
    if MONGO_USER and MONGO_PASS:
        _mongo.cuckoo.authenticate(MONGO_USER, MONGO_PASS)
    MONGO = _mongo[MONGO_DB]
except Exception as e:
    raise Exception("Unable to connect to Mongo: %s" % e)

if cfg.elasticsearch.get("enabled"):
    try:
        import elasticsearch
    except ImportError:
        raise Exception("ElasticSearch is enabled but not installed, aborting!")

    hosts = []
    for host in cfg.elasticsearch.get("hosts", "127.0.0.1:9200").split(","):
        if host.strip():
            hosts.append(host.strip())

    ELASTIC = elasticsearch.Elasticsearch(hosts)
    ELASTIC_INDEX = cfg.elasticsearch.get("index", "cuckoo")
else:
    ELASTIC = None

MOLOCH_ENABLED = cfg.moloch.get("enabled")
MOLOCH_HOST = cfg.moloch.get("host")

# In case we have VPNs enabled we need to initialize through the following
# two methods as they verify the interaction with VPNs as well as gather
# which VPNs are available (for representation upon File/URL submission).
from cuckoo.core.startup import init_rooter, init_routing

init_rooter()
init_routing()

DEBUG = False

# Database settings. We don't need it.
DATABASES = {}

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale.
USE_L10N = True

# Disabling time zone support and using local time for web interface and storage.
# See: https://docs.djangoproject.com/en/1.5/ref/settings/#time-zone
USE_TZ = False
TIME_ZONE = None

# Unique secret key generator. Secret key will be placed at $CWD/.secret_key.
if not os.path.exists(cwd("web", ".secret_key")):
    # Using the same generation schema of Django startproject.
    from django.utils.crypto import get_random_string
    SECRET_KEY = get_random_string(50, "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)")

    open(cwd("web", ".secret_key"), "wb").write(SECRET_KEY)
else:
    SECRET_KEY = open(cwd("web", ".secret_key"), "rb").read()

# Absolute filesystem path to the directory that will hold user-uploaded files.
MEDIA_ROOT = "/static/"

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash.
MEDIA_URL = ""

# Absolute path to the directory static files should be collected to.
# Don't put anything in this directory yourself; store your static files
# in apps' "static/" subdirectories and in STATICFILES_DIRS.
STATIC_ROOT = ""

# URL prefix for static files.
STATIC_URL = "/static/"

# Additional locations of static files
STATICFILES_DIRS = (
    os.path.join(os.getcwd(), "static"),
)

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = (
    "django.contrib.staticfiles.finders.FileSystemFinder",
    "django.contrib.staticfiles.finders.AppDirectoriesFinder",
    "django.contrib.staticfiles.finders.DefaultStorageFinder",
)

MIDDLEWARE_CLASSES = (
    "django.middleware.common.CommonMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    # Cuckoo headers.
    "web.headers.CuckooHeaders",
)

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [
            "templates",
        ],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": {
                "django.core.context_processors.request"
            }
        }
    },
]

ROOT_URLCONF = "web.urls"

# Python dotted path to the WSGI application used by Django's runserver.
WSGI_APPLICATION = "web.wsgi.application"

INSTALLED_APPS = (
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    # "django.contrib.sites",
    # "django.contrib.messages",
    "django.contrib.staticfiles",
    "django_extensions",
    # Uncomment the next line to enable the admin:
    "django.contrib.admin",
    # Uncomment the next line to enable admin documentation:
    # "django.contrib.admindocs",
    "analysis",
)

LOGIN_REDIRECT_URL = "/"

# Fix to avoid migration warning in django 1.7 about test runner (1_6.W001).
# In future it could be removed: https://code.djangoproject.com/ticket/23469
TEST_RUNNER = "django.test.runner.DiscoverRunner"

# A sample logging configuration. The only tangible logging
# performed by this configuration is to send an email to
# the site admins on every HTTP 500 error when DEBUG=False.
# See http://docs.djangoproject.com/en/dev/topics/logging for
# more details on how to customize your logging configuration.
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {
        "require_debug_false": {
            "()": "django.utils.log.RequireDebugFalse"
        }
    },
    "handlers": {
        "mail_admins": {
            "level": "ERROR",
            "filters": ["require_debug_false"],
            "class": "django.utils.log.AdminEmailHandler"
        },
        # Log django request to log file. Uncomment to enable.
        # "log_file": {
        #     "level": "DEBUG",
        #     "class": "logging.handlers.RotatingFileHandler",
        #     "filename": cwd("log", "django.log"),
        #     "maxBytes": 1024*1024*16, # 16 megabytes
        #     "backupCount": 3, # keep 3 copies
        # },
    },
    "loggers": {
        "django.request": {
            "handlers": ["mail_admins"],
            "level": "ERROR",
            "propagate": True,
        },
        # Log django request to log file. Uncomment to enable.
        # "django.request": {
        #     "handlers": ["log_file"],
        #     "level": "DEBUG",
        # },
    }
}

# Import local settings.
execfile(cwd("web", "local_settings.py"), globals(), locals())
