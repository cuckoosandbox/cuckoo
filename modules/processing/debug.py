# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import codecs
import logging
import os

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.core.database import Database

log = logging.getLogger(__name__)

class Logfile(list):
    def __init__(self, filepath):
        list.__init__(self)
        self.filepath = filepath

    def __iter__(self):
        try:
            for line in codecs.open(self.filepath, "rb", "utf-8"):
                yield line
        except Exception as e:
            log.info("Error decoding %s: %s", self.filepath, e)

    def __nonzero__(self):
        return bool(os.path.getsize(self.filepath))

class Debug(Processing):
    """Analysis debug information."""

    def run(self):
        """Run debug analysis.
        @return: debug information dict.
        """
        self.key = "debug"
        debug = {"log": [], "cuckoo": [], "errors": []}

        if os.path.exists(self.log_path):
            try:
                f = codecs.open(self.log_path, "rb", "utf-8")
                debug["log"] = f.readlines()
            except ValueError as e:
                raise CuckooProcessingError("Error decoding %s: %s" %
                                            (self.log_path, e))
            except (IOError, OSError) as e:
                raise CuckooProcessingError("Error opening %s: %s" %
                                            (self.log_path, e))

        if os.path.exists(self.cuckoolog_path):
            debug["cuckoo"] = Logfile(self.cuckoolog_path)

        for error in Database().view_errors(int(self.task["id"])):
            debug["errors"].append(error.message)

        if os.path.exists(self.mitmerr_path):
            mitmerr = open(self.mitmerr_path, "rb").read()
            if mitmerr:
                debug["errors"].append(mitmerr)

        return debug
