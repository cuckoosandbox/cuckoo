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

import logging
import pkgutil

import cuckoo.processing.sigs as sigs

class BaseSignature:
    def __init__(self):
        self.name        = ""
        self.description = ""
        self.severity    = 0
        self.alert       = False
        self.enabled     = True

    def process(self, results = None):
        raise NotImplementedError

class SignaturesProcessor:
    def __init__(self):
        self.signatures = []
        self.package = sigs
        self.prefix = self.package.__name__ + "."

    def process(self, results = None):
        log = logging.getLogger("Processing.SignaturesProcessor")
        
        for loader, name, ispkg in pkgutil.iter_modules(self.package.__path__, self.prefix):
            module = __import__(name,
                                globals(), 
                                locals(),
                                ['Signature'],
                                -1)

            try:
                sig = module.Signature()
            except AttributeError:
                continue

            if sig.enabled:
                matched = False
                
                try:
                    matched = sig.process(results)
                except NotImplementedError:
                    continue
            else:
                continue

            if matched:
                log.info("Signature \"%s\" matched!" % sig.name)

                self.signatures.append({"name" : sig.name,
                                        "description" : sig.description,
                                        "severity" : sig.severity,
                                        "alert" : sig.alert})
            else:
                log.info("Signature \"%s\" did not match." % sig.name)

        return self.signatures
