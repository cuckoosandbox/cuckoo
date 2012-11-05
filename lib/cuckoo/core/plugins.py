# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import imp
from collections import defaultdict

from lib.cuckoo.common.exceptions import CuckooCriticalError

_modules = defaultdict(dict)

def import_plugin(name):
    try:
        __import__(name, globals(), locals(), ["dummy"], -1)
    except ImportError as e:
        raise CuckooCriticalError("Unable to import plugin: %s" % e)

def import_package(package):
    prefix = package.__name__ + "."
    for loader, name, ispkg in pkgutil.iter_modules(package.__path__, prefix):
        if ispkg:
            continue

        __import__(name, globals(), locals(), ["dummy"], -1)

def register_plugin(group, name):
    global _modules

    if not group in _modules:
        _modules[group] = [name]
    else:
        if not name in _modules[group]:
            _modules[group].append(name)

def list_plugins(group=None):
    if group:
        return _modules[group]
    else:
        return _modules