# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import pkgutil
import inspect
import logging
from collections import defaultdict

from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.abstracts import MachineManager
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.abstracts import Signature
from lib.cuckoo.common.abstracts import Report

log = logging.getLogger(__name__)

_modules = defaultdict(dict)

def import_plugin(name):
    try:
        module = __import__(name, globals(), locals(), ["dummy"], -1)
    except ImportError as e:
        raise CuckooCriticalError("Unable to import plugin \"%s\": %s"
                                  % (name, e))
    else:
        load_plugins(module)

def import_package(package):
    prefix = package.__name__ + "."
    for loader, name, ispkg in pkgutil.iter_modules(package.__path__, prefix):
        if ispkg:
            continue

        import_plugin(name)

def load_plugins(module):
    for name, value in inspect.getmembers(module):
        if inspect.isclass(value):
            if issubclass(value, MachineManager) and value is not MachineManager:
                register_plugin("machinemanagers", value)
            elif issubclass(value, Processing) and value is not Processing:
                register_plugin("processing", value)
            elif issubclass(value, Signature) and value is not Signature:
                register_plugin("signatures", value)
            elif issubclass(value, Report) and value is not Report:
                register_plugin("reporting", value)

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
