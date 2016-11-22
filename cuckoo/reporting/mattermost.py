# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import hashlib
import requests

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooReportError, CuckooOperationalError

class Mattermost(Report):
    """Notifies about finished analysis via Mattermost webhook."""

    def run(self, results):
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

        filename = results.get("target", {}).get("file", {}).get("name", "")
        if self.options.get("hash_filename"):
            filename = hashlib.sha256(filename).hexdigest()

        post += "File : {0} ::: Score : **{1}** ::: ".format(
            filename, results.get("info", {}).get("score")
        )

        if self.options.get("show_virustotal"):
            post += "**VT : {0} / {1}**\n".format(
                results.get("virustotal", {}).get("positives"),
                results.get("virustotal", {}).get("total"),
            )

        if self.options.get("show_signatures"):
            post += "**Signatures** ::: {0} \n".format(" : ".join(sigs))

        if self.options.get("show_urls"):
            post += "**URLS**\n`{0}`".format(
                "\n".join(urls).replace(".", "[.]")
            )

        data = {
            "username": self.options.get("username"),
            "text": post,
        }

        headers = {
            "Content-Type": "application/json",
        }

        try:
            requests.post(
                self.options.get("url"),
                headers=headers,
                data=json.dumps(data)
            ).raise_for_status()
        except Exception as e:
            raise CuckooReportError(
                "Failed posting message to Mattermost: %s" % e
            )
