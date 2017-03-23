# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import base64
import codecs
import datetime
import glob
import io
import jinja2
import logging
import os
import random

try:
    logging.getLogger("weasyprint").setLevel(logging.ERROR)

    import weasyprint
    HAVE_WEASYPRINT = True
except ImportError:
    HAVE_WEASYPRINT = False

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooReportError
from cuckoo.misc import cwd

class SingleFile(Report):
    """Stores report in a single-file HTML and/or PDF format."""

    fonts = [{
        "family": "Roboto",
        "weight": 400,
        "style": "normal",
        "file": {
            "src": "Roboto-Regular-webfont.woff",
            "format": "woff",
        },
    }, {
        "family": "Roboto",
        "weight": 400,
        "style": "italic",
        "file": {
            "src": "Roboto-Italic-webfont.woff",
            "format": "woff",
        },
    }, {
        "family": "Roboto",
        "weight": 700,
        "style": "normal",
        "file": {
            "src": "Roboto-Bold-webfont.woff",
            "format": "woff",
        },
    }, {
        "family": "Roboto",
        "weight": 500,
        "style": "normal",
        "file": {
            "src": "Roboto-Medium-webfont.woff",
            "format": "woff",
        },
    }, {
        "family": "FontAwesome",
        "weight": "normal",
        "style": "normal",
        "file": {
            "src": "fontawesome-webfont.woff2",
            "format": "woff2",
        },
    }]

    mime_types = {
        "svg": "image/svg+xml",
        "ttf": "application/x-font-ttf",
        "otf": "application/x-font-opentype",
        "woff": "application/font-woff",
        "woff2": "application/font-woff2",
        "eot": "application/vnd.ms-fontobject",
        "sfnt": "application/font-sfnt",
        "png": "image/png",
        "gif": "image/gif",
        "jpg": "image/jpeg",
    }

    path_base = cwd("html", private=True)

    def run(self, results):
        report = self.generate_jinja2_template(results)

        if self.options.get("html"):
            report_path = os.path.join(self.reports_path, "report.html")
            codecs.open(report_path, "wb", encoding="utf-8").write(report)

        if self.options.get("pdf"):
            if not HAVE_WEASYPRINT:
                raise CuckooReportError(
                    "The weasyprint library hasn't been installed on your "
                    "Operating System and as such we can't generate a PDF "
                    "report for you. You can install 'weasyprint' manually "
                    "by running 'pip install weasyprint' or by compiling and "
                    "installing package yourself."
                )

            report_path = os.path.join(self.reports_path, "report.pdf")
            f = weasyprint.HTML(io.BytesIO(report.encode("utf8")))
            f.write_pdf(report_path)

    def generate_jinja2_template(self, results):
        template = open(cwd("html", "report.html", private=True), "rb").read()

        env = jinja2.environment.Environment(
            autoescape=True,
            loader=jinja2.loaders.FileSystemLoader(self.path_base),
            trim_blocks=False, lstrip_blocks=True
        )

        return env.from_string(template).render(
            task=self.task, filename=os.path.basename(self.task["target"]),
            results=results, date=datetime.datetime.now(),
            images=self.combine_images(), css=self.combine_css(),
            fonts=self.index_fonts(), scripts=self.combine_js(),
            screenshots=self.combine_screenshots(results),
        )

    def combine_css(self):
        """Scans the static/css/ directory and concatenates stylesheets"""
        css_includes = []
        for filepath in glob.glob("%s/static/css/*.css" % self.path_base):
            css_includes.append(open(filepath, "rb").read().decode("utf8"))
        return "\n".join(css_includes)

    def combine_js(self):
        """Scans the static/js/ directory and concatenates js files"""
        js_includes = []
        # Note: jquery-2.2.4.min.js must be the first file.
        filepaths = sorted(glob.glob("%s/static/js/*.js" % self.path_base))
        for filepath in filepaths:
            js_includes.append(
                open(filepath, "rb").read().strip().decode("utf8")
            )
        return "\n".join(js_includes)

    def index_fonts(self):
        fonts = []
        for font in self.fonts:
            filepath = os.path.join(
                self.path_base, "static", "fonts", font["file"]["src"]
            )
            fonts.append({
                "family": font["family"],
                "weight": font["weight"],
                "style": font["style"],
                "url": self.css_inline_font(
                    font["file"]["format"],
                    base64.b64encode(open(filepath, "rb").read())
                )
            })
        return fonts

    def combine_screenshots(self, results, num=4, shuffle=True):
        screenshots = results.get("screenshots", [])

        # Select N random screenshots.
        shots = range(len(screenshots))
        if shuffle:
            random.shuffle(shots)

        shot_includes = []
        for idx in shots[:num]:
            filepath = screenshots[idx]["path"]
            shot_includes.append({
                "selector": "shot-%d" % idx,
                "name": os.path.basename(filepath),
                "css": self.css_inline_image(
                    "shot-%d" % idx, "jpg",
                    base64.b64encode(open(filepath, "rb").read())
                ),
            })

        return shot_includes

    def combine_images(self):
        """Create a CSS string representation of all files in static/img/."""
        img_includes = []
        for imgpath in glob.glob("%s/static/img/*.png" % self.path_base):
            name, ext = os.path.splitext(os.path.basename(imgpath))
            img_includes.append(self.css_inline_image(
                name, ext.lstrip("."),
                base64.b64encode(open(imgpath, "rb").read())
            ))

        return "\n".join(img_includes)

    def css_inline_image(self, name, extension, content):
        return "div.img-%s{background: url(data:%s;base64,%s);}" % (
            name, self.mime_types[extension], content
        )

    def css_inline_font(self, extension, content):
        return "url(data:%s;charset=utf-8;base64,%s) format('%s')" % (
            self.mime_types[extension], content, extension
        )
