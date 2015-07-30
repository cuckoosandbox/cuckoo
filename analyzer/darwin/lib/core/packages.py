#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

from ..dtrace.apicalls import apicalls

import inspect
from os import sys, path

def choose_package_class(file_type, file_name, suggestion=None):
    if suggestion is not None:
        name = suggestion
    else:
        name = _guess_package_name(file_type, file_name)

    if not name:
        return None

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
    elif "Mach-O" in file_type and "executable" in file_type:
        return "macho"
    elif "directory" in file_type and (file_name.endswith(".app") or file_name.endswith(".app/")):
        return "app"
    elif "Zip archive" in file_type and file_name.endswith(".zip"):
        return "zip"
    else:
        return None


class Package(object):
    """ Base analysis package """

    def __init__(self, target, host, **kwargs):
        if not target or not host:
            raise Exception("Package(): `target` and `host` arguments are required")

        self.host = host
        self.target = target
        # Any analysis options?
        if "options" in kwargs:
            self.options = kwargs["options"]
        else:
            self.options = {}
        # A timeout for analysis
        if "timeout" in kwargs:
            self.timeout = kwargs["timeout"]
        # Command-line arguments for the target.
        if "args" in self.options:
            self.args = self.options["args"]
        else:
            self.args = []
        # Choose an analysis method
        if "method" in self.options:
            self.method = self.options["method"]
        else:  # fallback
            self.method = "apicalls"
        # Should our target be launched as root or not
        if "run_as_root" in self.options:
            self.run_as_root = _string_to_bool(self.options["run_as_root"])
        else:
            self.run_as_root = False
        # Our target may touch some files; keep an eye on them
        self.touched_files = []

    def prepare(self):
        """ Preparation routine. Do anything you want here. """
        pass

    def start(self):
        """ Runs an analysis process.
        This function is a generator.
        """
        self.prepare()

        if self.method == "apicalls":
            self.apicalls_analysis()
        else:
            raise Exception("Unsupported analysis method")

    def apicalls_analysis(self):
        kwargs = {
            'args': self.args,
            'timeout': self.timeout,
            'run_as_root': self.run_as_root
        }
        for call in apicalls(self.target, **kwargs):
            self.host.send_api(call)
            suspicious = ["fopen", "freopen", "open"]
            if call.api in suspicious and call.api not in self.touched_files:
                self.handle_file(call.args[0])

    def handle_file(self, filepath):
        # Is it a relative path? Suppose it's relative to our dtrace working directory
        if not path.isfile(filepath):
            filepath = path.join(path.dirname(__file__), "..", "dtrace", filepath)
        self.touched_files += [filepath]

def _string_to_bool(raw):
    if not isinstance(raw, basestring):
        raise Exception("Unexpected input: not a string :/")
    return raw.lower() in ("yes", "true", "t", "1")
