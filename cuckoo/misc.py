# Copyright (C) 2016-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ctypes
import errno
import importlib
import logging
import multiprocessing
import os
import subprocess
import sys
import types

try:
    import pwd
    HAVE_PWD = True
except ImportError:
    HAVE_PWD = False

import cuckoo

from cuckoo.common.defines import (
    WIN_PROCESS_QUERY_INFORMATION, WIN_ERR_STILL_ALIVE
)
from cuckoo.common.exceptions import CuckooStartupError

log = logging.getLogger(__name__)

# Cuckoo Working Directory base path.
_root = None
_raw = None

# Normalized Cuckoo version (i.e., "2.0.5.3" in setup is "2.0.5" here). This
# because we use StrictVersion() later on which doesn't accept "2.0.5.3".
version = "2.0.6"

def set_cwd(path, raw=None):
    global _root, _raw
    _root = path
    _raw = raw

def cwd(*args, **kwargs):
    """Returns absolute path to this file in the Cuckoo Working Directory or
    optionally - when private=True has been passed along - to our private
    Cuckoo Working Directory which is not configurable."""
    if kwargs.get("private"):
        return os.path.join(cuckoo.__path__[0], "private", *args)
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
    sys.modules["lib.cuckoo.common"] = sys.modules["cuckoo.common"]

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

    # Trigger an import on $CWD/signatures/. This will automatically import
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

class Pidfile(object):
    def __init__(self, name):
        """Manage pidfile of given name."""
        self.name = name
        self.filepath = cwd("pidfiles", "%s.pid" % name)
        self.pid = None

    def create(self):
        """Creates pidfile for the current process."""
        with open(self.filepath, "wb") as f:
            f.write(str(os.getpid()))

    def remove(self):
        """Remove pidfile if it exists."""
        if os.path.exists(self.filepath):
            os.remove(self.filepath)

    def exists(self):
        """Check if a pidfile (and its associated process) exists."""
        if not os.path.exists(self.filepath):
            return False
        return self.proc_exists(self.read())

    def read(self):
        """Read PID from pidfile."""
        try:
            self.pid = int(open(self.filepath, "rb").read())
        except ValueError:
            self.pid = None
        return self.pid

    def proc_exists(self, pid):
        """Returns boolean if the process exists or None when unsupported."""
        if not pid:
            return False

        if is_windows():
            from ctypes import windll, wintypes
            dw_exit = wintypes.DWORD()
            proc_h = windll.kernel32.OpenProcess(
                WIN_PROCESS_QUERY_INFORMATION, 0, pid
            )
            windll.kernel32.GetExitCodeProcess(proc_h, ctypes.byref(dw_exit))
            windll.kernel32.CloseHandle(proc_h)
            return dw_exit.value == WIN_ERR_STILL_ALIVE

        if is_linux() or is_macosx():
            # Send signal 0 to process. Exception will be thrown if it does
            # not exist or there is no permission to send to this process.
            # This indicates a process does exist.
            try:
                os.kill(pid, 0)
            except OSError as e:
                return e.errno == errno.EPERM
            return True

    @staticmethod
    def get_active_pids():
        """Return a dict containing active pids.
        Key is the pidfile name and value is pid"""
        pids = {}

        for filename in os.listdir(cwd("pidfiles")):
            name, _ = os.path.splitext(filename)
            pidfile = Pidfile(name)
            if pidfile.exists():
                pids[name] = pidfile.pid

        return pids

def make_list(obj):
    if isinstance(obj, (tuple, list)):
        return list(obj)
    return [obj]

def format_command(*args):
    raw = cwd(raw=True)
    if raw == "." or raw == "~/.cuckoo":
        command = "cuckoo "
    elif " " in raw or "'" in raw:
        command = 'cuckoo --cwd "%s" ' % raw
    else:
        command = "cuckoo --cwd %s " % raw
    return command + " ".join(args)
