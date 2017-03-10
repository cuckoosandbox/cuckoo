# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import codecs
import base64
import random

from glob import glob
from copy import copy
from datetime import datetime

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooReportError
from cuckoo.common.objects import File
from cuckoo.misc import cwd
from cuckoo.web.controllers.analysis.analysis import AnalysisController

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

        analysis_id = results["info"]["id"]

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

        constants = {
            "date_now": datetime.now()
        }

        signatures = {}
        if results["signatures"]:
            signatures = AnalysisController.signatures(
                task_id=results["signatures"],
                signatures=results["signatures"])

        behavioral = AnalysisController.get_behavior(analysis_id, report=results)
        screenshots = self.combine_screenshots(results["screenshots"])

        try:
            template = self.generate_jinja2_template(
                results=results,
                behavioral=behavioral,
                signatures=signatures,
                constants=constants,
                screenshots=screenshots)
        except Exception as e:
            raise CuckooReportError("Failed to generate HTML report: %s" % e)

        try:
            report_path = os.path.join(self.reports_path, "report.html")
            with codecs.open(report_path, "w", encoding="utf-8") as report:
                report.write(template)
        except (TypeError, IOError) as e:
            raise CuckooReportError("Failed to write HTML report: %s" % e)

        return True

    def generate_jinja2_template(self, **kwargs):
        jinja2_env = Environment(autoescape=True)
        jinja2_env.loader = FileSystemLoader(self.path_base)

        html_file = open("%s/report.html" % self.path_base, "r")
        html_contents = html_file.read()
        html_file.close()

        head = self.generate_html_head(kwargs["results"]["info"]["id"])
        html_contents = html_contents.replace("{{ head }}", head)
        template_env = Environment(autoescape=True,
                                   loader=FileSystemLoader(self.path_base),
                                   trim_blocks=False,
                                   lstrip_blocks=True)
        
        return template_env.from_string(html_contents).render(kwargs)

    def generate_html_head(self, analysis_id):
        """
        Generates the <head> tag for report.html.
        It'll combine files from `static/css/`, `static/fonts/`
        and `static/img/`.  So that external resources are not needed.
        Non-plaintext files (fonts/images) are converted
        to base64 encoded data URI's
        @param analysis_id: analysis ID
        @return: the <head> tag
        """
        return """
            <meta charset="UTF-8">
            <title>Cuckoo Report %d</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta name="description" content="">
            <meta name="author" content="">
            <style>
            /* IMAGES */
            %s

            /* CSS */
            %s

            /* FONTS */
            %s
            </style>
            <script>
            %s
            </script>
        """ % (analysis_id,
               self.combine_images(),
               self.combine_css(),
               self.combine_fonts(),
               self.combine_js())

    def combine_css(self):
        """Scans the `static/css/ directory and concatenates stylesheets"""
        css_includes = ""
        for css_path in glob("%s/static/css/*.css" % self.path_base):
            css_file = open(css_path, "r")
            css_data = css_file.read().decode('utf-8')
            css_includes += "%s\n\n" % css_data
            css_file.close()

        return css_includes

    def combine_js(self):
        """Scans the `static/js/ directory and concatenates js files"""
        js_includes = ""
        js_paths = glob("%s/static/js/*.js" % self.path_base)
        js_paths.insert(0, "%s/static/js/lib/jquery-2.2.4.min.js" % self.path_base)

        for js_path in js_paths:
            js_file = open(js_path, "r")
            js_data = js_file.read().decode('utf-8')
            js_includes += "%s\n\n" % js_data
            js_file.close()

        return js_includes

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

    def combine_screenshots(self, screenshots, num=4, shuffle=True):
        if not screenshots:
            return

        shots = copy(screenshots)
        if shuffle:
            random.shuffle(shots)

        shots = shots[0:num]
        shot_includes = []
        for shot_id in range(0, len(shots)):
            shot_name = "shot-%d" % shot_id
            shot_css = self.generate_b64_image_css(
                img_name=shot_name,
                img_ext="jpg",
                img_data_b64=shots[shot_id]["data"])

            shot_includes.append({
                "selector": shot_name,
                "name": shots[shot_id]["id"],
                "css": shot_css,
                "ext": "jpg",
                "id": shot_id
            })

        return shot_includes

    def combine_images(self):
        """
        Scans the `static/img/ directory for images and
        creates CSS classes with base64 encoded data URI's"""
        img_includes = ""
        for img_path in glob("%s/static/img/*.png" % self.path_base):
            img_file = open(img_path, "r")
            img_spl = os.path.splitext(img_path)
            img_name = os.path.basename(img_spl[0])
            img_ext = img_spl[1]
            img_ext = img_ext.replace(".", "")
            img_data = img_file.read()
            img_file.close()

            img_data_b64 = base64.b64encode(img_data)
            img_includes += self.generate_b64_image_css(img_name, img_ext, img_data_b64)

        return img_includes

    @staticmethod
    def generate_b64_image_css(img_name, img_ext, img_data_b64):
        mime_types = {
            "png": "image/png",
            "gif": "image/gif",
            "jpg": "image/jpeg"
        }

        return """
            div.img-%s{
                background: url(data:%s;base64,%s);
            }
        """ % (img_name, mime_types[img_ext], img_data_b64)
