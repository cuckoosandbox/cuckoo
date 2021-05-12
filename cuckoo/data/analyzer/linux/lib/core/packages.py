#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

from ..common.apicalls import apicalls

import inspect
from os import sys, path, waitpid, environ
import logging
import time
import subprocess
from lib.common.results import NetlogFile
from lib.core.config import Config
from lib.api.process import Process

log = logging.getLogger(__name__)


def choose_package_class(file_type=None, file_name="", suggestion=None):
    if suggestion is not None:
        name = suggestion
    else:
        name = _guess_package_name(file_type, file_name)
        if not name:
            log.info("_guess_package_name failed")
            log.info(file_type)
            log.info(file_name)
            name = "generic"

    full_name = "modules.packages.%s" % name
    try:
        # FIXME(rodionovd):
        # I couldn't figure out how to make __import__ import anything from
        # the (grand)parent package, so here I just patch the PATH
        sys.path.append(path.abspath(path.join(path.dirname(__file__), '..', '..')))
        # Since we don't know the package class yet, we'll just import everything
        # from this module and then try to figure out the required member class
        module = __import__(full_name, globals(), locals(), ['*'])
    except ImportError:
        raise Exception("Unable to import package \"{0}\": it does not "
                        "exist.".format(name))
    try:
        pkg_class = _found_target_class(module, name)
    except IndexError as err:
        raise Exception("Unable to select package class (package={0}): "
                        "{1}".format(full_name, err))
    return pkg_class


def _found_target_class(module, name):
    """ Searches for a class with the specific name: it should be
    equal to capitalized $name.
    """
    members = inspect.getmembers(module, inspect.isclass)
    return [x[1] for x in members if x[0] == name.capitalize()][0]


def _guess_package_name(file_type, file_name):
    if "Bourne-Again" in file_type or "bash" in file_type:
        return "bash"
    elif "Zip archive" in file_type:
        return "zip"
    elif "gzip compressed data" in file_type:
        return "zip"
    elif "PDF document" in file_type or file_name.endswith(".pdf"):
        return "pdf"
    elif "Composite Document File V2 Document" in file_type or file_name.endswith(".doc"):
        return "doc"
    elif "Microsoft Word" in file_type or file_name.endswith(".docx"):
        return "doc"
    elif "ELF" in file_type:
        return "generic"
    elif "Unicode text" in file_type or file_name.endswith(".js"):
        return "js"
    else:
        return None


class Package(object):
    """ Base analysis package """

    def __init__(self, target, **kwargs):
        if not target:
            raise Exception("Package(): `target` and `host` arguments are required")

        self.target = target
        # Any analysis options?
        self.options = kwargs.get("options", {})
        # A timeout for analysis
        self.timeout = kwargs.get("timeout", None)
        # Command-line arguments for the target.
        self.args = self.options.get("args", [])
        # Choose an analysis method (or fallback to apicalls)
        self.method = self.options.get("method", "apicalls")
        # Should our target be launched as root or not
        self.run_as_root = _string_to_bool(self.options.get("run_as_root", "False"))
        #free: do not inject our monitor.
        self.free = self.options.get("free", None)
        self.proc = None
        self.pids = []

    def set_pids(self, pids):
        """Update list of monitored PIDs in the package context.
        @param pids: list of pids.
        """
        self.pids = pids

    def prepare(self):
        """ Preparation routine. Do anything you want here. """
        pass

    def start(self):
        """ Runs an analysis process.
        This function is a generator.
        """
        target_name = self.options.get("filename")
        if target_name:
            filepath = path.join(environ.get("TEMP", "/tmp"), target_name)
            # Remove the trailing slash (if any)
            if filepath.endswith("/"):
                self.target = filepath[:-1]
            else:
                self.target = filepath
        self.prepare()
        if self.free:
            self.normal_analysis()
            return self.proc.pid
        elif self.method == "apicalls":
            self.apicalls_analysis()
            return self.proc.pid
        else:
            raise Exception("Unsupported analysis method. Try `apicalls`.")

    def check(self):
        """Check."""
        return True

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

    def get_pids(self):
        return []

    def apicalls_analysis(self):
        kwargs = {
            'args': self.args,
            'timeout': self.timeout,
            'run_as_root': self.run_as_root
        }
        log.info(self.target)
        cmd = apicalls(self.target, **kwargs)
        stap_start = time.time()
        log.info(cmd)
        self.proc = subprocess.Popen(cmd, env={"XAUTHORITY":"/root/.Xauthority", "DISPLAY":":0"},
                                     stderr=subprocess.PIPE, shell=True)

        while "systemtap_module_init() returned 0" not in self.proc.stderr.readline():
            #log.debug(self.proc.stderr.readline())
            pass

        stap_stop = time.time()
        log.info("Process startup took %.2f seconds" % (stap_stop - stap_start))
        return True

    def normal_analysis(self):
        kwargs = {
            'args': self.args,
            'timeout': self.timeout,
            'run_as_root': self.run_as_root
        }

        #cmd = apicalls(self.target, **kwargs)
        cmd = "%s %s" % (self.target, " ".join(kwargs["args"]))
        stap_start = time.time()
        self.proc = subprocess.Popen(cmd, env={"XAUTHORITY":"/root/.Xauthority", "DISPLAY":":0"},
                                     stderr=subprocess.PIPE, shell=True)

        log.debug(self.proc.stderr.readline())

        stap_stop = time.time()
        log.info("Process startup took %.2f seconds" % (stap_stop - stap_start))
        return True

    @staticmethod
    def _upload_file(local, remote):
        if path.exists(local):
            nf = NetlogFile(remote)
            with open(local, "rb") as f:
                for chunk in f:
                    nf.sock.sendall(chunk)  # dirty direct send, no reconnecting
            nf.close()

    def stop(self):
        log.info("Package requested stop")
        try:
            r = self.proc.poll()
            log.debug("stap subprocess retval %r", r)
            self.proc.kill()
            #subprocess.check_call(["sudo","kill", str(self.proc.pid)])
            waitpid(self.proc.pid, 0)
            self._upload_file("stap.log", "logs/all.stap")
        except Exception as e:
            log.warning("Exception uploading log: %s", e)

def _string_to_bool(raw):
    if not isinstance(raw, basestring):
        raise Exception("Unexpected input: not a string :/")
    return raw.lower() in ("yes", "true", "t", "1")
