import os

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
    def run(self, results):
        if not HAVE_MAKO:
            raise CuckooReportError("Failed to generate HTML report: python Mako library is not installed")

        lookup = TemplateLookup(directories=[os.path.join(CUCKOO_ROOT, "lib/cuckoo/web/")],
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
