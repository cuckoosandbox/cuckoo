# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import base64

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

try:
    from mako.template import Template
    from mako.lookup import TemplateLookup
    HAVE_MAKO = True
except ImportError:
    HAVE_MAKO = False

class ReportHTML(Report):
    """Stores report in HTML format."""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        if not HAVE_MAKO:
            raise CuckooReportError("Failed to generate HTML report: python Mako library is not installed")

        shots_path = os.path.join(self.analysis_path, "shots")
        if os.path.exists(shots_path):
            shots = []
            counter = 1
            for shot_name in os.listdir(shots_path):
                if not shot_name.endswith(".jpg"):
                    continue

                shot_path = os.path.join(shots_path, shot_name)

                if os.path.getsize(shot_path) == 0:
                    continue

                shot = {}
                shot["id"] = counter
                shot["data"] = base64.b64encode(open(shot_path, "rb").read())
                shots.append(shot)

                counter += 1

            shots.sort(key=lambda shot: shot["id"])
            results["screenshots"] = shots
        else:
            results["screenshots"] = []

        lookup = TemplateLookup(directories=[os.path.join(CUCKOO_ROOT, "data", "html")],
                                output_encoding='utf-8',
                                encoding_errors='replace')
        
        template = lookup.get_template("report.html")

        try:
            html = template.render(**results)
        except Exception as e:
            raise CuckooReportError("Failed to generate HTML report: %s" % e.message)
        
        try:
            report = open(os.path.join(self.reports_path, "report.html"), "w")
            report.write(html)
            report.close()
        except (TypeError, IOError) as e:
            raise CuckooReportError("Failed to generate HTML report: %s" % e.message)

        return True
