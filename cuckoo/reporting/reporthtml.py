# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import jinja2
import codecs
import base64
import random

from glob import glob
from copy import copy
from datetime import datetime
from collections import OrderedDict
from jinja2 import Environment, FileSystemLoader

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

        constants = {
            "date_now": datetime.now()
        }

        signatures = self.format_signatures(results["signatures"])
        screenshots = self.combine_screenshots(results["screenshots"])

        #TODO: Code resembles web/controllers/analysis/api.py, should be in a controller that we can import
        # def behavior_get_processes
        behavioral = {}

        plist = {
            "data": [],
            "status": True
        }

        for process in results.get("behavior", {}).get("generic", []):
            plist["data"].append({
                "process_name": process["process_name"],
                "pid": process["pid"]
            })

        # sort returning list of processes by their name
        plist["data"] = sorted(plist["data"], key=lambda k: k["process_name"])

        for proc in plist["data"]:
            # def behavior_get_watchers
            behavior_generic = results["behavior"]["generic"]
            process = [z for z in behavior_generic if z["pid"] == proc["pid"]]

            if not process:
                continue
            else:
                process = process[0]

            data = {}
            for category, watchers in {  # def behavior_get_watcherlist
                "files":
                    ["file_opened", "file_read"],
                "registry":
                    ["regkey_opened", "regkey_written", "regkey_read"],
                "mutexes":
                    ["mutex"],
                "directories":
                    ["directory_created", "directory_removed", "directory_enumerated"],
                "processes":
                    ["command_line", "dll_loaded"],
            }.iteritems():
                for watcher in watchers:
                    if watcher in process["summary"]:
                        if category not in data:
                            data[category] = [watcher]
                        else:
                            data[category].append(watcher)

            # def behavior_get_watcher
            for category, events in data.iteritems():
                if not behavioral.has_key(category):
                    behavioral[category] = {}

                if not behavioral[category].has_key(proc["pid"]):
                    behavioral[category][proc["process_name"]] = {
                        "pid": proc["pid"],
                        "process_name": proc["process_name"],
                        "events": {}
                    }

                for event in events:
                    if not behavioral[category][proc["process_name"]]["events"].has_key(event):
                        behavioral[category][proc["process_name"]]["events"][event] = []

                    for _event in process["summary"][event]:
                        behavioral[category][proc["process_name"]]["events"][event].append(_event)

        def tmp_test():
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

        tmp_test()

        return True

    def generate_jinja2_template(self, **kwargs):
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
        It'll combine files from `static/css/`, `static/fonts/`
        and `static/img/`.  So that external resources are not needed.
        Non-plaintext files (fonts/images) are converted
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
            /* IMAGES */
            %s

            /* CSS */
            %s

            /* FONTS */
            %s
            </style>
        """ % (analysis_id,
               self.combine_images(),
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
