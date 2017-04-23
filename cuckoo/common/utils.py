# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import bs4
import chardet
import datetime
import inspect
import io
import jsbeautifier
import json
import logging
import os
import platform
import re
import string
import sys
import threading
import warnings
import xmlrpclib

from distutils.version import StrictVersion
from django.core.validators import URLValidator

from cuckoo.common.constants import GITHUB_URL, ISSUES_PAGE_URL
from cuckoo.misc import cwd, version

log = logging.getLogger(__name__)

# Don't allow all characters in "string.printable", as newlines, carriage
# returns, tabs, \x0b, and \x0c may mess up reports.
PRINTABLE_CHARACTERS = (
    string.letters + string.digits + string.punctuation + " \t\r\n"
)

def convert_char(c):
    """Escapes characters.
    @param c: dirty char.
    @return: sanitized char.
    """
    if c in PRINTABLE_CHARACTERS:
        return c
    else:
        return "\\x%02x" % ord(c)

def is_printable(s):
    """Test if a string is printable."""
    for c in s:
        if c not in PRINTABLE_CHARACTERS:
            return False
    return True

def convert_to_printable(s):
    """Convert char to printable.
    @param s: string.
    @return: sanitized string.
    """
    if is_printable(s):
        return s
    return "".join(convert_char(c) for c in s)

def validate_hash(h):
    """Validates a hash by length and contents."""
    if len(h) not in (32, 40, 64, 128):
        return False

    return bool(re.match("[0-9a-fA-F]*$", h))

def validate_url(url):
    """Validates an URL using Django's built-in URL validator"""
    val = URLValidator(schemes=["http", "https"])

    try:
        val(url)
        return url
    except:
        pass

    try:
        val("http://%s" % url)
        return "http://%s" % url
    except:
        pass

class TimeoutServer(xmlrpclib.ServerProxy):
    """Timeout server for XMLRPC.
    XMLRPC + timeout - still a bit ugly - but at least gets rid of setdefaulttimeout
    inspired by http://stackoverflow.com/questions/372365/set-timeout-for-xmlrpclib-serverproxy
    (although their stuff was messy, this is cleaner)
    @see: http://stackoverflow.com/questions/372365/set-timeout-for-xmlrpclib-serverproxy
    """
    def __init__(self, *args, **kwargs):
        timeout = kwargs.pop("timeout", None)
        kwargs["transport"] = TimeoutTransport(timeout=timeout)
        xmlrpclib.ServerProxy.__init__(self, *args, **kwargs)

    def _set_timeout(self, timeout):
        t = self._ServerProxy__transport
        t.timeout = timeout
        # If we still have a socket we need to update that as well.
        if hasattr(t, "_connection") and t._connection[1] and t._connection[1].sock:
            t._connection[1].sock.settimeout(timeout)

class TimeoutTransport(xmlrpclib.Transport):
    def __init__(self, *args, **kwargs):
        self.timeout = kwargs.pop("timeout", None)
        xmlrpclib.Transport.__init__(self, *args, **kwargs)

    def make_connection(self, *args, **kwargs):
        conn = xmlrpclib.Transport.make_connection(self, *args, **kwargs)
        if self.timeout is not None:
            conn.timeout = self.timeout
        return conn

class Singleton(type):
    """Singleton.
    @see: http://stackoverflow.com/questions/6760685/creating-a-singleton-in-python
    """
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

class ThreadSingleton(type):
    """Singleton per thread."""
    _instances = threading.local()

    def __call__(cls, *args, **kwargs):
        if not getattr(cls._instances, "instance", None):
            cls._instances.instance = super(ThreadSingleton, cls).__call__(*args, **kwargs)
        return cls._instances.instance

def to_unicode(s):
    """Attempt to fix non uft-8 string into utf-8. It tries to guess input encoding,
    if fail retry with a replace strategy (so undetectable chars will be escaped).
    @see: fuller list of encodings at http://docs.python.org/library/codecs.html#standard-encodings
    """

    def brute_enc(s2):
        """Trying to decode via simple brute forcing."""
        encodings = ("ascii", "utf8", "latin1")
        for enc in encodings:
            try:
                return unicode(s2, enc)
            except UnicodeDecodeError:
                pass
        return None

    def chardet_enc(s2):
        """Guess encoding via chardet."""
        enc = chardet.detect(s2)["encoding"]

        try:
            return unicode(s2, enc)
        except UnicodeDecodeError:
            pass
        return None

    # If already in unicode, skip.
    if isinstance(s, unicode):
        return s

    # First try to decode against a little set of common encodings.
    result = brute_enc(s)

    # Try via chardet.
    if not result:
        result = chardet_enc(s)

    # If not possible to convert the input string, try again with
    # a replace strategy.
    if not result:
        result = unicode(s, errors="replace")

    return result

def classlock(f):
    """Classlock decorator (created for database.Database).
    Used to put a lock to avoid sqlite errors.
    """
    def inner(self, *args, **kwargs):
        curframe = inspect.currentframe()
        calframe = inspect.getouterframes(curframe, 2)

        if calframe[1][1].endswith("database.py"):
            return f(self, *args, **kwargs)

        with self._lock:
            return f(self, *args, **kwargs)

    return inner

class SuperLock(object):
    def __init__(self):
        self.tlock = threading.Lock()

    def __enter__(self):
        self.tlock.acquire()

    def __exit__(self, type, value, traceback):
        self.tlock.release()

GUIDS = {}

def guid_name(guid):
    if not GUIDS:
        for line in open(cwd("guids.txt", private=True)):
            try:
                guid_, name, url = line.strip().split()
            except:
                log.debug("Invalid GUID entry: %s", line)
                continue

            GUIDS["{%s}" % guid_] = name

    return GUIDS.get(guid)

def exception_message():
    """Creates a message describing an unhandled exception."""
    def get_os_release():
        """Returns detailed OS release."""
        if platform.linux_distribution()[0]:
            return " ".join(platform.linux_distribution())
        elif platform.mac_ver()[0]:
            return "%s %s" % (platform.mac_ver()[0], platform.mac_ver()[2])
        else:
            return "Unknown"

    msg = (
        "Oops! Cuckoo failed in an unhandled exception!\nSometimes bugs are "
        "already fixed in the development release, it is therefore "
        "recommended to retry with the latest development release available "
        "%s\nIf the error persists please open a new issue at %s\n\n" %
        (GITHUB_URL, ISSUES_PAGE_URL)
    )

    msg += "=== Exception details ===\n"
    msg += "Cuckoo version: %s\n" % version
    msg += "OS version: %s\n" % os.name
    msg += "OS release: %s\n" % get_os_release()
    msg += "Python version: %s\n" % platform.python_version()
    msg += "Python implementation: %s\n" % platform.python_implementation()
    msg += "Machine arch: %s\n" % platform.machine()

    try:
        import pip

        msg += "Modules: %s\n" % " ".join(sorted(
            "%s:%s" % (package.key, package.version)
            for package in pip.get_installed_distributions()
        ))
    except ImportError:
        pass

    msg += "\n"
    return msg

_jsbeautify_blacklist = [
    "",
    "error: Unknown p.a.c.k.e.r. encoding.\n",
]

_jsbeautify_lock = threading.Lock()

def jsbeautify(javascript):
    """Beautifies Javascript through jsbeautifier and ignore some messages."""
    with _jsbeautify_lock:
        origout, sys.stdout = sys.stdout, io.StringIO()
        javascript = jsbeautifier.beautify(javascript)

        if sys.stdout.getvalue() not in _jsbeautify_blacklist:
            log.warning("jsbeautifier returned error: %s", sys.stdout.getvalue())

        sys.stdout = origout
    return javascript

def htmlprettify(html):
    """Beautifies HTML through BeautifulSoup4."""
    # The following ignores the following bs4 warning:
    # UserWarning: "." looks like a filename, not markup.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", lineno=182)
        return bs4.BeautifulSoup(html, "html.parser").prettify()

def json_default(obj):
    """JSON serializer for objects not serializable by default json code"""
    if hasattr(obj, "to_dict"):
        return obj.to_dict()

    if isinstance(obj, datetime.datetime):
        if obj.utcoffset() is not None:
            obj = obj - obj.utcoffset()
        return {"$dt": obj.isoformat()}
    raise TypeError("Type not serializable")

def json_hook(obj):
    """JSON object hook, deserializing datetimes ($date)"""
    if "$dt" in obj:
        return datetime.datetime.strptime(obj["$dt"], "%Y-%m-%dT%H:%M:%S.%f")
    return obj

def json_encode(obj, **kwargs):
    """JSON encoding wrapper that handles datetime objects"""
    return json.dumps(obj, default=json_default, **kwargs)

def json_decode(x):
    """JSON decoder that does ugly first-level datetime handling"""
    return json.loads(x, object_hook=json_hook)

def parse_bool(value):
    """Attempt to parse a boolean value."""
    if value in ("true", "True", "yes", "1", "on"):
        return True
    if value in ("false", "False", "None", "no", "0", "off"):
        return False
    return bool(int(value))

def supported_version(version, minimum, maximum):
    """Checks if a version number is supported as per the minimum and maximum
    version numbers."""
    if minimum and StrictVersion(version) < StrictVersion(minimum):
        return False

    if maximum and StrictVersion(version) > StrictVersion(maximum):
        return False

    return True

def list_of(l, cls):
    if not isinstance(l, (tuple, list)):
        return False
    for value in l:
        if not isinstance(value, cls):
            return False
    return True

def list_of_ints(l):
    return list_of(l, (int, long))

def list_of_strings(l):
    return list_of(l, basestring)
