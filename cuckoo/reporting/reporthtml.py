# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import jinja2
import codecs
import base64

from glob import glob
from datetime import datetime
from collections import OrderedDict

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooReportError
from cuckoo.common.objects import File
from cuckoo.misc import cwd

try:
    from jinja2.environment import Environment
    from jinja2.loaders import FileSystemLoader

    HAVE_JINJA2 = True
except ImportError:
    HAVE_JINJA2 = False


class ReportHTML(Report):
    """Stores report in HTML format."""

    path_base = cwd("html", private=True)

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        if not HAVE_JINJA2:
            raise CuckooReportError(
                "Failed to generate HTML report: Jinja2 library is not "
                "installed (install `pip install jinja2`)")

        shots_path = os.path.join(self.analysis_path, "shots")
        if os.path.exists(shots_path):
            shots = []
            counter = 1
            for shot_name in os.listdir(shots_path):
                if not shot_name.endswith(".jpg"):
                    continue

                shot_path = os.path.join(shots_path, shot_name)
                if not os.path.getsize(shot_path):
                    continue

                shot = {}
                shot["id"] = os.path.splitext(File(shot_path).get_name())[0]
                shot["data"] = base64.b64encode(open(shot_path, "rb").read())
                shots.append(shot)

                counter += 1

            shots.sort(key=lambda shot: shot["id"])
            results["screenshots"] = shots
        else:
            results["screenshots"] = []

        env = Environment(autoescape=True)
        env.loader = FileSystemLoader(self.path_base)

        processed = None
        mapping = [
            ("file_read", "File", "Read"),
            ("file_written", "File", "Written"),
            ("file_deleted", "File", "Deleted"),
            ("file_opened", "File", "Opened"),
            ("file_copied", "File", "Copied"),
            ("file_moved", "File", "Moved"),
            ("connects_ip", "Network", "Connects IP"),
            ("resolves_url", "Network", "Resolves URL"),
            ("fetches_url", "Network", "Fetches URL"),
            ("connects_host", "Network", "Connects Host"),
            ("downloads_file_url", "Network", "Downloads File URL"),
            ("directory_created", "Directory", "Created"),
            ("directory_removed", "Directory", "Removed"),
            ("directory_enumerated", "Directory", "Enumerated"),
            ("regkey_opened", "Registry Key", "Opened"),
            ("regkey_deleted", "Registry Key", "Deleted"),
            ("regkey_read", "Registry Key", "Read"),
            ("regkey_written", "Registry Key", "Written"),
            ("mutex", "Mutex", "Accessed"),
        ]

        constants = {
            "date_now": datetime.now().strftime("%Y/%m/%d %H:%M")
        }

        processed = {}
        for proc in results.get("behavior", {}).get("generic", []):
            for orig, cat, subcat in mapping:
                if cat not in processed:
                    processed[cat] = {}

                if subcat not in processed[cat]:
                    processed[cat][subcat] = []

                # Special handling required for file moved/copied.
                if orig == "file_moved" or orig == "file_copied":
                    for src, dst in proc.get("summary", {}).get(orig, []):
                        entry = "%s -> %s" % (src, dst)
                        processed[cat][subcat].append(entry)
                    continue

                if "summary" in proc and orig in proc["summary"]:
                    for content in proc["summary"][orig]:
                        processed[cat][subcat].append(content)

        def x(results, processed, mapping, constants):
            try:
                html_file = open("%s/report.html" % self.path_base, "r")
                html_contents = html_file.read()
                html_file.close()

                head = self.generate_html_head(results["info"]["id"])
                html_contents = html_contents.replace("{{ head }}", head)

                html_jinja2 = jinja2.Environment().from_string(html_contents)

                signatures = self.format_signatures(results["signatures"])

                html_template = html_jinja2.render({
                    "results": results,
                    "processed": processed,
                    "mapping": mapping,
                    "signatures": signatures,
                    "constants": constants})

            except Exception as e:
                raise CuckooReportError("Failed to generate HTML report: %s" % e)

            try:
                report_path = os.path.join(self.reports_path, "report.html")
                with codecs.open(report_path, "w", encoding="utf-8") as report:
                    report.write(html_template)
            except (TypeError, IOError) as e:
                raise CuckooReportError("Failed to write HTML report: %s" % e)

        x(results, processed, mapping, constants)

        return True

    def format_signatures(self, signatures):
        """Returns an OrderedDict containing a lists with signatures based on severity"""
        data = OrderedDict()
        for signature in signatures:
            severity = signature["severity"]
            if severity > 3:
                severity = 3
            if not data.has_key(severity):
                data[severity] = []
            data[severity].append(signature)
        return data

    def generate_html_head(self, analysis_id):
        """
        Generates the <head> tag for report.html.
        It'll combine files from both `static/css/` and `static/fonts/`
        so that external CSS includes are not needed.
        Non-plaintext files (like fonts) are converted
        to base64 encoded data URI's
        @param analysis_id: analysis ID
        @return: the <head> tag
        """
        return """
            <meta charset="UTF-8">
            <title>Cuckoo Report #%d</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta name="description" content="">
            <meta name="author" content="">
            <style>
            /* CSS */
            %s

            /* FONTS */
            %s
            </style>
        """ % (analysis_id,
               self.combine_css(),
               self.combine_fonts())

    def combine_css(self):
        """Scans the `static/css/ directory for stylesheets and concatenates them"""
        css_includes = ""
        for css_path in glob("%s/static/css/*.css" % self.path_base):
            css_file = open(css_path, "r")
            css_data = css_file.read()
            css_includes += "%s\n\n" % css_data
            css_file.close()

        return css_includes

    def combine_fonts(self):
        fonts = [{
            "family": "Roboto",
            "weight": 400,
            "style": "normal",
            "src": [{
                "src": "Roboto-Regular-webfont.woff",
                "format": "woff"
            }]}, {
            "family": "Roboto",
            "weight": 400,
            "style": "italic",
            "src": [{
                "src": "Roboto-Italic-webfont.woff",
                "format": "woff"
            }]}, {
            "family": "Roboto",
            "weight": 700,
            "style": "normal",
            "src": [{
                "src": "Roboto-Bold-webfont.woff",
                "format": "woff"}
            ]}, {
            "family": "Roboto",
            "weight": 500,
            "style": "normal",
            "src": [{
                "src": "Roboto-Medium-webfont.woff",
                "format": "woff"}
            ]}, {
            "family": "FontAwesome",
            "weight": "normal",
            "style": "normal",
            "src": [{
                "src": "fontawesome-webfont.woff2",
                "format": "woff2"}
            ]}]

        mime_types = {
            "svg": "image/svg+xml",
            "ttf": "application/x-font-ttf",
            "otf": "application/x-font-opentype",
            "woff": "application/font-woff",
            "woff2": "application/font-woff2",
            "eot": "application/vnd.ms-fontobject",
            "sfnt": "application/font-sfnt"
        }

        font_includes = ""

        for font in fonts:
            font_face = """
                @font-face {
                    font-family: '%s';
                    src: {{ urls }};
                    font-weight: %s;
                    font-style: %s;
                }
                """ % (font["family"], font["weight"], font["style"])

            urls = []
            for src in font["src"]:
                font_name = src["src"]
                font_format = src["format"]
                font_ext = os.path.splitext(font_name)[1]
                font_ext = font_ext.replace(".", "")
                font_mime = mime_types[font_ext]
                font_path = "%s/static/fonts/%s" % (self.path_base, src["src"])

                font = open(font_path, "r")
                font_read = font.read()
                font_b64 = base64.b64encode(font_read)

                data_uri = "url(data:%s;charset=utf-8;base64,%s) format('%s')" % (
                    font_mime, font_b64, font_format)
                urls.append(data_uri)

                font.close()

            font_face = font_face.replace("{{ urls }}", ",".join(urls))
            font_includes += font_face

        return font_includes
