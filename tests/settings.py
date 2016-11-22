# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import pymongo

from cuckoo.misc import cwd

SECRET_KEY = "A"*40
ROOT_URLCONF = "web.urls"

MEDIA_ROOT = "/static/"
STATIC_URL = "/static/"

STATICFILES_DIRS = cwd("..", "web", "static", private=True)

STATICFILES_FINDERS = (
    "django.contrib.staticfiles.finders.FileSystemFinder",
    "django.contrib.staticfiles.finders.AppDirectoriesFinder",
    "django.contrib.staticfiles.finders.DefaultStorageFinder",
)

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

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [
            cwd("..", "web", "templates", private=True)
        ],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": {
                "django.core.context_processors.request"
            }
        },
    },
]

# Test database.
MONGO = pymongo.MongoClient("localhost", 27017)["cuckootest"]
