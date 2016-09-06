# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import hashlib
import logging
import os
import sys
import shutil
import ntpath
import string
import tempfile
import xmlrpclib
import inspect
import platform
import threading
import json
import multiprocessing
import warnings

from cStringIO import StringIO
from datetime import datetime

from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.config import Config

from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_VERSION
from lib.cuckoo.common.constants import GITHUB_URL, ISSUES_PAGE_URL

try:
    import bs4
    HAVE_BS4 = True
except ImportError:
    HAVE_BS4 = False

try:
    import chardet
    HAVE_CHARDET = True
except ImportError:
    HAVE_CHARDET = False

try:
    import jsbeautifier
    HAVE_JSBEAUTIFIER = True
except ImportError:
    HAVE_JSBEAUTIFIER = False

log = logging.getLogger(__name__)

def create_folders(root=".", folders=[]):
    """Create directories.
    @param root: root path.
    @param folders: folders list to be created.
    @raise CuckooOperationalError: if fails to create folder.
    """
    for folder in folders:
        create_folder(root, folder)

def create_folder(root=".", folder=None):
    """Create directory.
    @param root: root path.
    @param folder: folder name to be created.
    @raise CuckooOperationalError: if fails to create folder.
    """
    folder_path = os.path.join(root, folder)
    if folder and not os.path.isdir(folder_path):
        try:
            os.makedirs(folder_path)
        except OSError:
            raise CuckooOperationalError("Unable to create folder: %s" %
                                         folder_path)

def delete_folder(folder):
    """Delete a folder and all its subdirectories.
    @param folder: path to delete.
    @raise CuckooOperationalError: if fails to delete folder.
    """
    if os.path.exists(folder):
        try:
            shutil.rmtree(folder)
        except OSError:
            raise CuckooOperationalError("Unable to delete folder: "
                                         "{0}".format(folder))

# Don't allow all characters in "string.printable", as newlines, carriage
# returns, tabs, \x0b, and \x0c may mess up reports.
PRINTABLE_CHARACTERS = \
    string.letters + string.digits + string.punctuation + " \t\r\n"

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
    """ Test if a string is printable."""
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

def datetime_to_iso(timestamp):
    """Parse a datatime string and returns a datetime in iso format.
    @param timestamp: timestamp string
    @return: ISO datetime
    """
    return datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").isoformat()

def get_filename_from_path(path):
    """Cross-platform filename extraction from path.
    @param path: file path.
    @return: filename.
    """
    dirpath, filename = ntpath.split(path)
    return filename if filename else ntpath.basename(dirpath)

def store_temp_file(filedata, filename, path=None):
    """Store a temporary file.
    @param filedata: content of the original file.
    @param filename: name of the original file.
    @param path: optional path for temp directory.
    @return: path to the temporary file.
    """
    filename = get_filename_from_path(filename)

    # Reduce length (100 is arbitrary).
    filename = filename[:100]

    options = Config()
    # Create temporary directory path.
    if path:
        target_path = path
    else:
        tmp_path = options.cuckoo.get("tmppath", "/tmp")
        target_path = os.path.join(tmp_path, "cuckoo-tmp")
    if not os.path.exists(target_path):
        os.mkdir(target_path)

    tmp_dir = tempfile.mkdtemp(prefix="upload_", dir=target_path)
    tmp_file_path = os.path.join(tmp_dir, filename)
    with open(tmp_file_path, "wb") as tmp_file:
        # If filedata is file object, do chunked copy.
        if hasattr(filedata, "read"):
            chunk = filedata.read(1024)
            while chunk:
                tmp_file.write(chunk)
                chunk = filedata.read(1024)
        else:
            tmp_file.write(filedata)

    return tmp_file_path

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
    if not result and HAVE_CHARDET:
        result = chardet_enc(s)

    # If not possible to convert the input string, try again with
    # a replace strategy.
    if not result:
        result = unicode(s, errors="replace")

    return result

def cleanup_value(v):
    """Cleanup utility function, strips some unwanted parts from values."""
    v = str(v)
    if v.startswith("\\??\\"):
        v = v[4:]
    return v

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
        self.mlock = multiprocessing.Lock()

    def __enter__(self):
        self.tlock.acquire()
        self.mlock.acquire()

    def __exit__(self, type, value, traceback):
        self.mlock.release()
        self.tlock.release()

def hash_file(method, filepath):
    """Calculates an hash on a file by path.
    @param method: callable hashing method
    @param path: file path
    @return: computed hash string
    """
    f = open(filepath, "rb")
    h = method()
    while True:
        buf = f.read(1024 * 1024)
        if not buf:
            break
        h.update(buf)
    return h.hexdigest()

def md5_file(filepath):
    return hash_file(hashlib.md5, filepath)

def sha1_file(filepath):
    return hash_file(hashlib.sha1, filepath)

def sha256_file(filepath):
    return hash_file(hashlib.sha256, filepath)

GUIDS = {}

def guid_name(guid):
    if not GUIDS:
        for line in open(os.path.join(CUCKOO_ROOT, "data", "guids.txt")):
            try:
                guid, name, url = line.strip().split()
            except:
                log.debug("Invalid GUID entry: %s", line)
                continue

            GUIDS["{%s}" % guid] = name

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
    msg += "Cuckoo version: %s\n" % CUCKOO_VERSION
    msg += "OS version: %s\n" % os.name
    msg += "OS release: %s\n" % get_os_release()
    msg += "Python version: %s\n" % sys.version.split()[0]
    msg += "Machine arch: %s\n" % platform.machine()

    git_version = os.path.join(CUCKOO_ROOT, ".git", "refs", "heads", "master")
    if os.path.exists(git_version):
        try:
            msg += "Git version: %s\n" % open(git_version, "rb").read().strip()
        except:
            pass

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
    if not HAVE_JSBEAUTIFIER:
        return javascript

    with _jsbeautify_lock:
        origout, sys.stdout = sys.stdout, StringIO()
        javascript = jsbeautifier.beautify(javascript)

        if sys.stdout.getvalue() not in _jsbeautify_blacklist:
            log.warning("jsbeautifier returned error: %s", sys.stdout.getvalue())

        sys.stdout = origout
    return javascript

def htmlprettify(html):
    """Beautifies HTML through BeautifulSoup4."""
    if not HAVE_BS4:
        return html

    # The following ignores the following bs4 warning:
    # UserWarning: "." looks like a filename, not markup.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", lineno=182)
        return bs4.BeautifulSoup(html, "html.parser").prettify()

def json_default(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, datetime):
        if obj.utcoffset() is not None:
            obj = obj - obj.utcoffset()
        return {"$dt": obj.isoformat()}
    raise TypeError("Type not serializable")

def json_hook(obj):
    """JSON object hook, deserializing datetimes ($date)"""
    if "$dt" in obj:
        x = obj["$dt"]
        return datetime.strptime(x, "%Y-%m-%dT%H:%M:%S.%f")
    return obj

def json_encode(obj, **kwargs):
    """JSON encoding wrapper that handles datetime objects"""
    return json.dumps(obj, default=json_default, **kwargs)

def json_decode(x):
    """JSON decoder that does ugly first-level datetime handling"""
    return json.loads(x, object_hook=json_hook)

def versiontuple(v):
    """Return the version as a tuple for easy comparison."""
    return tuple(int(x) for x in v.split("."))
