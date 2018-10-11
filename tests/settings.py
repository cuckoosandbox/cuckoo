# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.template.base import TemplateSyntaxError

from cuckoo.misc import cwd

class InvalidString(str):
    def __mod__(self, other):
        raise TemplateSyntaxError(
            "Undefined variable or unknown value for: %s" % other
        )

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

MIDDLEWARE_CLASSES = (
    # Cuckoo headers.
    "web.middle.CuckooHeaders",
    "web.errors.ExceptionMiddleware",
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
            },
            "string_if_invalid": InvalidString("%s"),
        },
    },
]

# Enable debug mode.
DEBUG = True
