# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

try:
    import bs4
    HAVE_BS4 = True
except ImportError:
    HAVE_BS4 = False

from lib.cuckoo.common.abstracts import Signature

class HtmlFlash(Signature):
    name = "html_flash"
    description = "Embeds Flash content in a HTML page"
    severity = 3
    categories = ["exploit"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "CElement_put_innerHTML",

    def on_call(self, call, process):
        if not HAVE_BS4:
            return

        html = bs4.BeautifulSoup(call["arguments"]["html"], "html.parser")

        results = []
        for obj in html.find_all("object"):
            params = {}
            for param in obj.find_all("param"):
                key, value = param.attrs.get("name"), param.attrs.get("value")
                if key and value:
                    params[key.lower()] = value.lower()

            if params not in results and params.get("movie"):
                results.append(params)

                self.mark(
                    movie=params["movie"],
                    flashvars=params.get("flashvars", ""),
                )

        return self.has_marks()

    def on_complete(self):
        # Slightly hacky but will have to do for now.
        for http in self.get_results("network", {}).get("http_ex", []):
            if "x-flash-version:" in http["request"]:
                self.mark(md5=http["md5"], sha1=http["sha1"])

        for http in self.get_results("network", {}).get("https_ex", []):
            if "x-flash-version:" in http["request"]:
                self.mark(md5=http["md5"], sha1=http["sha1"])

        return self.has_marks()
