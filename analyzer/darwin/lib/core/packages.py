#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

from ..dtrace.apicalls import apicalls

import inspect
from sets import Set
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

    # Our target may touch some files; keep an eye on them
    touched_files = Set()

    def __init__(self, target, host, **kwargs):
        if not target or not host:
            raise Exception("Package(): `target` and `host` arguments are required")

        self.host = host
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
            raise Exception("Unsupported analysis method. Try `apicalls`.")

    def apicalls_analysis(self):
        kwargs = {
            'args': self.args,
            'timeout': self.timeout,
            'run_as_root': self.run_as_root
        }
        for call in apicalls(self.target, **kwargs):
            # Send this API to Cuckoo host
            self.host.send_api(call)
            # Handle file IO APIs
            self.handle_files(call)

    def handle_files(self, call):
        """ Remember what files our target has been working with during the analysis"""
        def makeabs(filepath):
            # Is it a relative path? Suppose it's relative to our dtrace working directory
            if not path.isfile(filepath):
                filepath = path.join(path.dirname(__file__), "..", "dtrace", filepath)
            return filepath
        if call.api in ["fopen", "freopen", "open"]:
            self.open_file(makeabs(call.args[0]))
        if call.api in ["rename"]:
            self.move_file(makeabs(call.args[0]), makeabs(call.args[1]))
        if call.api in ["copyfile"]:
            self.copy_file(makeabs(call.args[0]), makeabs(call.args[1]))
        if call.api in ["remove", "unlink"]:
            self.remove_file(makeabs(call.args[0]))

    def open_file(self, filepath):
        self.touched_files.add(filepath)

    def move_file(self, frompath, topath):
        # Remove old reference if needed
        if frompath in self.touched_files:
            self.touched_files.remove(frompath)
        self.touched_files.add(topath)

    def copy_file(self, frompath, topath):
        # Add both files to the watch list
        self.touched_files.update([frompath, topath])

    def remove_file(self, filepath):
        # TODO(rodionovd): we're actually unable to dump this file
        # because well, it was removed
        self.touched_files.add(filepath)

def _string_to_bool(raw):
    if not isinstance(raw, basestring):
        raise Exception("Unexpected input: not a string :/")
    return raw.lower() in ("yes", "true", "t", "1")
