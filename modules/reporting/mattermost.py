# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import hashlib

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.exceptions import CuckooOperationalError

class Mattermost(Report):
    """Notifies about finished analysis via Mattermost webhook."""

    def run(self, results):
        if not HAVE_REQUESTS:
            raise CuckooOperationalError(
                "The Mattermost processing module requires the requests "
                "library (install with `pip install requests`)"
            )

        sigs, urls = [], []
        for sig in results.get("signatures", []):
            sigs.append(sig.get("name"))
            if sig.get("name") == "network_http":
                for http in sig.get("marks"):
                    urls.append(http.get("ioc"))

        post = "Finished analyze ::: [{0}]({1}{0}) ::: ".format(
            results.get("info", {}).get("id"),
            self.options.get("myurl")
        )

        if results.get("info").get("category") == "file":
            target = results.get("target", {}).get("file", {}).get("name", "")
            if self.options.get("hash-filename"):
                target = hashlib.sha256(target).hexdigest()
        elif results.get("info").get("category") == "url":
            target = results.get("target", {}).get("url", "")
            if self.options.get("hash-url"):
                target = hashlib.sha256(target).hexdigest()

        post += "Target : {0} ::: Score : **{1}** ::: ".format(
            target, results.get("info", {}).get("score")
        )

        if self.options.get("show-virustotal"):
            post += "**VT : {0} / {1}**\n".format(
                results.get("virustotal", {}).get("positives"),
                results.get("virustotal", {}).get("total"),
            )

        if self.options.get("show-signatures"):
            post += "**Signatures** ::: {0} \n".format(" : ".join(sigs))

        if self.options.get("show-urls"):
            post += "**URLS**\n`{0}`".format(
                "\n".join(urls).replace(".", "[.]")
            )

        data = {
            "username": self.options.get("username"),
            "text": post,
        }

        headers = {"Content-Type": "application/json"}

        try:
            r = requests.post(
                self.options.get("url"),
                headers=headers,
                data=json.dumps(data)
            )

            # note that POST max size is 4000 chars by default
            if r.status_code != 200:
                raise CuckooReportError (
                    "Failed posting message due to : {0}".format(r.text)
                )
        except Exception as e:
            raise CuckooReportError(
                "Failed posting message to Mattermost: {0}".format(e)
            )
