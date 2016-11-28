# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import imp
import inspect
import logging
import multiprocessing
import os.path
import pkg_resources
import subprocess
import sys

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
    if kwargs.pop("private", False):
        return os.path.join(cuckoo.__path__[0], "data-private", *args)
    elif kwargs.pop("raw", False):
        return _raw
    elif kwargs.pop("root", False):
        return _root
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
    # We need to create each module separately.
    module_names = (
        "lib", "lib.cuckoo", "lib.cuckoo.common",
        "lib.cuckoo.common.abstracts",
    )

    for module_name in module_names:
        sys.modules[module_name] = imp.new_module(module_name)

    # Import this here in order to avoid recursive import statements.
    from cuckoo.common.abstracts import Signature
    sys.modules["lib.cuckoo.common.abstracts"].Signature = Signature

    # Don't clobber the Cuckoo Working Directory with .pyc files.
    dont_write_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True

    modules = {
        "android": dict(platform="android"),
        "cross": dict(),
        "darwin": dict(platform="darwin"),
        "network": dict(),
        "windows": dict(platform="windows"),
    }

    # Prepare a module for each signature directory.
    for modname in modules:
        module_name = "cuckoo.signatures.%s" % modname
        sys.modules[module_name] = imp.new_module(module_name)

    # Import each Signature that we find in the Cuckoo Working Directory.
    for dirpath, dirnames, filenames in os.walk(cwd("signatures")):
        for filename in filenames:
            if filename.endswith(".pyc") or filename.startswith("__init__"):
                continue

            # E.g., "cuckoo.signatures.network.network_http".
            category = os.path.basename(dirpath)
            module_name = "cuckoo.signatures.%s.%s" % (
                category, os.path.splitext(filename)[0]
            )
            module = imp.load_source(module_name, cwd(dirpath, filename))

            # Locate each Signature in this module and assign the
            # per-category attributes to it.
            for entry in module.__dict__.values():
                if not inspect.isclass(entry):
                    continue

                if not issubclass(entry, Signature) or entry == Signature:
                    continue

                for key, value in modules.get(category, {}).items():
                    setattr(entry, key, value)

    # Overwrite all Signatures that are in-place by all the Signatures that
    # have been registered at this point, literally.
    cuckoo.signatures.plugins[:] = Signature.__subclasses__()
    sys.dont_write_bytecode = dont_write_bytecode

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
