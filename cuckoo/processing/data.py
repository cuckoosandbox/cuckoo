# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2012  Claudio "nex" Guarnieri (nex@cuckoobox.org)
# http://www.cuckoobox.org
#
# This file is part of Cuckoo.
#
# Cuckoo is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Cuckoo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.

import os
import pkgutil
import logging

from cuckoo.processing.observers import Analysis, Signature
import cuckoo.processing.modules as modules 
import cuckoo.processing.signatures as signatures

class DataProcessor:
    def __init__(self, analysis_path):
        self.analysis_path = analysis_path

    def _populate(self, package):
        prefix = package.__name__ + "."
        for loader, name, ispkg in pkgutil.iter_modules(package.__path__, prefix):
            if ispkg:
                continue

            module = __import__(name,
                                globals(),
                                locals(),
                                ["THANKS PYTHON"],
                                -1)

    def process(self, results = None):
        results = {}
        log = logging.getLogger("Processing.DataProcessor")

        self._populate(modules)
        Analysis()
        for processor in Analysis.__subclasses__():
            current = processor(self.analysis_path)

            try:
                results[current.key] = current.process()
            except NotImplementedError:
                continue

        self._populate(signatures)
        Signature()

        matched_sigs = []

        for sig in Signature.__subclasses__():
            current_sig = sig()

            if not current_sig.enabled:
                continue

            try:
                matched = current_sig.process(results)
            except NotImplementedError:
                continue

            if matched:
                log.info("Signature \"%s\" matched!" % current_sig.name)

                matched_sigs.append({"name"        : current_sig.name,
                                     "description" : current_sig.description,
                                     "severity"    : current_sig.severity,
                                     "alert"       : current_sig.alert})

        results["signatures"] = matched_sigs

        return results
