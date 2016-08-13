# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import requests

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

class Mattermost(Report):
    """Notifies about finished analysis via Mattermost webhook."""

    def run(self, results):

        sigs = []
        urls = []
        for sig in results.get("signatures", {}):
            sigs.append(sig.get("name"))
            if sig.get("name") == "network_http":
                for http in sig.get("marks"):
                    urls.append(http.get("ioc"))

        data = {
            "text": "Finished analyze ::: [{0}]({4}{0}) ::: "
                    "File : {1} ::: "
                    "VT : {2} / {3} \n "
                    "SIGS ::: {5} \n "
                    "**URLS**\n `{6}`".format(
                        results.get("info").get("id"), 
                        results.get("target").get("file").get("name"), 
                        results.get("virustotal").get("total"), 
                        results.get("virustotal").get("positives"), 
                        self.options.get("myurl"), 
                        ' : '.join(sigs), '\n'.join(urls).replace(".", "[.]")
                    ) 
        }

        headers = {'Content-Type': 'application/json'}
        response = requests.post(self.options.get("url"), headers=headers, data=json.dumps(data))