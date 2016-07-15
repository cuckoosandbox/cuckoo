# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import glob
import os

from _winreg import CreateKey, SetValueEx, CloseKey, REG_DWORD, REG_SZ

from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

class Package(object):
    """Base abstract analysis package."""
    PATHS = []
    REGKEYS = []

    def __init__(self, options={}, analyzer=None):
        """@param options: options dict."""
        self.options = options
        self.analyzer = analyzer
        self.pids = []

        # Fetch the current working directory, defaults to $TEMP.
        if "curdir" in options:
            self.curdir = os.path.expandvars(options["curdir"])
        else:
            self.curdir = os.getenv("TEMP")

    def set_pids(self, pids):
        """Update list of monitored PIDs in the package context.
        @param pids: list of pids.
        """
        self.pids = pids

    def start(self, target):
        """Run analysis package.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def check(self):
        """Check."""
        return True

    def enum_paths(self):
        """Enumerate available paths."""
        basepaths = {
            "System32": [
                os.path.join(os.getenv("SystemRoot"), "System32"),
                os.path.join(os.getenv("SystemRoot"), "SysWOW64"),
            ],
            "ProgramFiles": [
                os.getenv("ProgramFiles").replace(" (x86)", ""),
                os.getenv("ProgramFiles(x86)"),
            ],
            "HomeDrive": [
                # os.path.join() doesn't work well if you give it just "C:"
                # so manually append a backslash.
                os.getenv("HomeDrive") + "\\",
            ],
        }

        for path in self.PATHS:
            basedir = path[0]
            for basepath in basepaths.get(basedir, [basedir]):
                if not basepath or not os.path.isdir(basepath):
                    continue

                yield os.path.join(basepath, *path[1:])

    def get_path(self, application):
        """Search for the application in all available paths.
        @param applicaiton: application executable name
        @return: executable path
        """
        for path in self.enum_paths():
            if os.path.isfile(path):
                return path

        raise CuckooPackageError("Unable to find any %s executable." %
                                 application)

    def get_path_glob(self, application):
        """Search for the application in all available paths with glob support.
        @param applicaiton: application executable name
        @return: executable path
        """
        for path in self.enum_paths():
            for path in glob.iglob(path):
                if os.path.isfile(path):
                    return path

        raise CuckooPackageError("Unable to find any %s executable." %
                                 application)

    def move_curdir(self, filepath):
        """Move a file to the current working directory so it can be executed
        from there.
        @param filepath: the file to be moved
        @return: the new filepath
        """
        outpath = os.path.join(self.curdir, os.path.basename(filepath))
        os.rename(filepath, outpath)
        return outpath

    def init_regkeys(self, regkeys):
        """Initializes the registry to avoid annoying popups, configure
        settings, etc.
        @param regkeys: the root keys, subkeys, and key/value pairs.
        """
        for rootkey, subkey, values in regkeys:
            key_handle = CreateKey(rootkey, subkey)

            for key, value in values.items():
                if isinstance(value, str):
                    SetValueEx(key_handle, key, 0, REG_SZ, value)
                elif isinstance(value, int):
                    SetValueEx(key_handle, key, 0, REG_DWORD, value)
                elif isinstance(value, dict):
                    self.init_regkeys([
                        [rootkey, "%s\\%s" % (subkey, key), value],
                    ])
                else:
                    raise CuckooPackageError("Invalid value type: %r" % value)

            CloseKey(key_handle)

    def execute(self, path, args, mode=None, maximize=False, env=None,
                source=None, trigger=None):
        """Starts an executable for analysis.
        @param path: executable path
        @param args: executable arguments
        @param mode: monitor mode - which functions to instrument
        @param maximize: whether the GUI should start maximized
        @param env: additional environment variables
        @param source: parent process of our process
        @param trigger: trigger to indicate analysis start
        @return: process pid
        """
        dll = self.options.get("dll")
        free = self.options.get("free")

        source = source or self.options.get("from")
        mode = mode or self.options.get("mode")

        if not trigger and self.options.get("trigger"):
            if self.options["trigger"] == "exefile":
                trigger = "file:%s" % path

        # Setup pre-defined registry keys.
        self.init_regkeys(self.REGKEYS)

        p = Process()
        if not p.execute(path=path, args=args, dll=dll, free=free,
                         curdir=self.curdir, source=source, mode=mode,
                         maximize=maximize, env=env, trigger=trigger):
            raise CuckooPackageError(
                "Unable to execute the initial process, analysis aborted."
            )

        return p.pid

    def package_files(self):
        """A list of files to upload to host.
        The list should be a list of tuples (<path on guest>, <name of file in package_files folder>).
        (package_files is a folder that will be created in analysis folder).
        """
        return None

    def finish(self):
        """Finish run.
        If specified to do so, this method dumps the memory of
        all running processes.
        """
        if self.options.get("procmemdump"):
            for pid in self.pids:
                p = Process(pid=pid)
                p.dump_memory()

        return True

class Auxiliary(object):
    def __init__(self, options={}, analyzer=None):
        self.options = options
        self.analyzer = analyzer
