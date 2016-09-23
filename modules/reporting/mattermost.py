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
        for sig in results.get("signatures", {}):
            sigs.append(sig.get("name"))
            if sig.get("name") == "network_http":
                for http in sig.get("marks"):
                    urls.append(http.get("ioc"))

        post = "Finished analyze ::: [{0}]({1}{0}) ::: ".format(
            results.get("info").get("id"),
            self.options.get("myurl")
        )

        filename = results.get("target").get("file").get("name")
        if self.options.get("hash-filename"):
            filename = hashlib.sha256(filename).hexdigest()

        post += "File : {0} ::: Score : **{1}** ::: ".format(
            filename, results.get("info").get("score")
        )

        if self.options.get("show-virustotal"):
            post += "**VT : {0} / {1}**\n".format(
                results.get("virustotal").get("positives"),
                results.get("virustotal").get("total"),
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
            requests.post(
                self.options.get("url"),
                headers=headers,
                data=json.dumps(data)
            )
        except Exception as e:
            raise CuckooReportError(
                "Failed posting message to Mattermost: %s" % e
            )
