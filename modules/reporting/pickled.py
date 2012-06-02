# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import pickle

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

class Pickled(Report):
    def run(self, results):
        try:
            pickle.dump(results, open(os.path.join(self.reports_path, "report.pickle"), "w"), 2)
        except (pickle.PickleError, IOError) as e:
            raise CuckooReportError("Failed to generate Pickle report: %s" % e.message)
