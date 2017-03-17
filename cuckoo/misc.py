# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ctypes
import importlib
import logging
import multiprocessing
import os.path
import pkg_resources
import subprocess
import sys
import types

try:
    import pwd
    HAVE_PWD = True
except ImportError:
    HAVE_PWD = False

import cuckoo

from cuckoo.common.exceptions import CuckooStartupError

log = logging.getLogger(__name__)

# Cuckoo Working Directory base path.
_root = None
_raw = None

version = pkg_resources.require("Cuckoo")[0].version

def set_cwd(path, raw=None):
    global _root, _raw
    _root = path
    _raw = raw

def cwd(*args, **kwargs):
    """Returns absolute path to this file in the Cuckoo Working Directory or
    optionally - when private=True has been passed along - to our private
    Cuckoo Working Directory which is not configurable."""
    if kwargs.get("private"):
        return os.path.join(cuckoo.__path__[0], "data-private", *args)
    elif kwargs.get("raw"):
        return _raw
    elif kwargs.get("root"):
        return _root
    elif kwargs.get("analysis"):
        return os.path.join(
            _root, "storage", "analyses", "%s" % kwargs["analysis"], *args
        )
    elif kwargs:
        raise RuntimeError(
            "Invalid arguments provided to cwd(): %r %r" % (args, kwargs)
        )
    else:
        return os.path.join(_root, *args)

def decide_cwd(cwd=None, exists=False):
    """Decides and sets the CWD, optionally checks if it's a valid CWD."""
    if not cwd:
        cwd = os.environ.get("CUCKOO_CWD")

    if not cwd:
        cwd = os.environ.get("CUCKOO")

    if not cwd and os.path.exists(".cwd"):
        cwd = "."

    if not cwd:
        cwd = "~/.cuckoo"

    dirpath = os.path.abspath(os.path.expanduser(cwd))
    if exists:
        if not os.path.exists(dirpath):
            raise CuckooStartupError(
                "Unable to start this Cuckoo command as the provided CWD (%r) "
                "is not present!" % dirpath
            )

        if not os.path.exists(os.path.join(dirpath, ".cwd")):
            raise CuckooStartupError(
                "Unable to start this Cuckoo command as the provided CWD (%r) "
                "is not a proper CWD!" % dirpath
            )

    set_cwd(dirpath, raw=cwd)
    return dirpath

def mkdir(*args):
    """Create a directory without throwing exceptions if it already exists."""
    dirpath = os.path.join(*args)
    if not os.path.isdir(dirpath):
        os.mkdir(dirpath)

def getuser():
    if HAVE_PWD:
        return pwd.getpwuid(os.getuid())[0]
    return ""

def load_signatures():
    """Loads additional Signatures from the Cuckoo Working Directory.

    This method is quite hacky in the sense that it magically imports
    Signatures from an arbitrary directory - one that doesn't belong to the
    Cuckoo package directly.

    Furthermore this method provides backwards compatibility with older
    Signatures which rely on the "lib.cuckoo.common.abstracts" import, one
    that can now be accessed as "cuckoo.common.abstracts".
    """
    # Forward everything from lib.cuckoo to "our" cuckoo module.
    sys.modules["lib"] = types.ModuleType("lib")
    sys.modules["lib.cuckoo"] = sys.modules["cuckoo"]

    # Import this here in order to avoid recursive import statements.
    from cuckoo.common.abstracts import Signature

    # Define Signature in such a way that it is equal to "our" Signature.
    sys.modules["lib.cuckoo.common.abstracts"] = types.ModuleType(
        "lib.cuckoo.common.abstracts"
    )
    sys.modules["lib.cuckoo.common.abstracts"].Signature = Signature

    # Don't clobber the Cuckoo Working Directory with .pyc files.
    dont_write_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True

    # Trigger an import on $CWD/signatures. This will automatically import
    # recursively down the various directories through the use of
    # enumerate_plugins(), which the Cuckoo Community adheres to. For this to
    # work we temporarily insert the CWD in Python's path.
    sys.path.insert(0, cwd())
    mod = importlib.import_module("signatures")
    sys.path.pop(0)

    # Restore bytecode option.
    sys.dont_write_bytecode = dont_write_bytecode

    # Index all of the available Signatures that have been located.
    for key, value in sorted(mod.__dict__.items()):
        if not key.startswith("_") and hasattr(value, "plugins"):
            cuckoo.signatures.extend(value.plugins)

def _worker(conn, func, *args, **kwargs):
    conn.send(func(*args, **kwargs))
    conn.close()

def dispatch(func, args=(), kwargs={}, timeout=60, process=True):
    """Dispatch a function call to a separate process or thread to execute with
    a maximum provided timeout. Note that in almost all occurrences a separate
    process should be used as otherwise we might end up with out-of-order
    locking mechanism instances, resulting in undefined behavior later on."""
    if not isinstance(args, tuple) or not isinstance(kwargs, dict):
        raise RuntimeError("args must be a tuple and kwargs a dict")

    if not process:
        raise RuntimeError("no support yet for dispatch(process=False)")

    parent, child = multiprocessing.Pipe(duplex=False)
    p = multiprocessing.Process(
        target=_worker, args=(child, func) + args, kwargs=kwargs
    )
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.terminate()
        parent.close()
        return

    ret = parent.recv()
    parent.close()
    return ret

def is_windows():
    return sys.platform == "win32"

def is_linux():
    return sys.platform == "linux2"

def is_macosx():
    return sys.platform == "darwin"

def Popen(*args, **kwargs):
    """Drops the close_fds argument on Windows platforms in certain situations
    where it'd otherwise cause an exception from the subprocess module."""
    if is_windows() and "close_fds" in kwargs:
        if "stdin" in kwargs or "stdout" in kwargs or "stderr" in kwargs:
            kwargs.pop("close_fds")

    return subprocess.Popen(*args, **kwargs)

def drop_privileges(username):
    """Drops privileges to selected user.
    @param username: drop privileges to this username
    """
    if not HAVE_PWD:
        sys.exit(
            "Unable to import pwd required for dropping privileges (note that "
            "privilege dropping is not supported under Windows)!"
        )

    try:
        user = pwd.getpwnam(username)
        os.setgroups((user.pw_gid,))
        os.setgid(user.pw_gid)
        os.setuid(user.pw_uid)
        os.putenv("HOME", user.pw_dir)
    except KeyError:
        sys.exit("Invalid user specified to drop privileges to: %s" % username)
    except OSError as e:
        sys.exit("Failed to drop privileges to %s: %s" % (username, e))

class Structure(ctypes.Structure):
    def as_dict(self):
        ret = {}
        for field, _ in self._fields_:
            value = getattr(self, field)
            if isinstance(value, Structure):
                ret[field] = value.as_dict()
            elif hasattr(value, "value"):
                ret[field] = value
            elif hasattr(value, "__getitem__"):
                ret[field] = value[:]
            else:
                ret[field] = value
        return ret
