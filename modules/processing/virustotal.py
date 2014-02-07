# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import urllib
import urllib2

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.common.objects import File

VIRUSTOTAL_FILE_URL = "https://www.virustotal.com/vtapi/v2/file/report"
VIRUSTOTAL_URL_URL = "https://www.virustotal.com/vtapi/v2/url/report"

class VirusTotal(Processing):
    """Gets antivirus signatures from VirusTotal.com"""

    def run(self):
        """Runs VirusTotal processing
        @return: full VirusTotal report.
        """
        self.key = "virustotal"
        virustotal = []

        key = self.options.get("key", None)
        if not key:
            raise CuckooProcessingError("VirusTotal API key not "
                                        "configured, skip")

        if self.task["category"] == "file":
            if not os.path.exists(self.file_path):
                raise CuckooProcessingError("File {0} not found, skipping it".format(self.file_path))

            resource = File(self.file_path).get_md5()
            url = VIRUSTOTAL_FILE_URL
        elif self.task["category"] == "url":
            resource = self.task["target"]
            url = VIRUSTOTAL_URL_URL

        data = urllib.urlencode({"resource": resource, "apikey": key})

        try:
            request = urllib2.Request(url, data)
            response = urllib2.urlopen(request)
            response_data = response.read()
        except urllib2.URLError as e:
            raise CuckooProcessingError("Unable to establish connection "
                                        "to VirusTotal: {0}".format(e))
        except urllib2.HTTPError as e:
            raise CuckooProcessingError("Unable to perform HTTP request to "
                                        "VirusTotal "
                                        "(http code={0})".format(e.code))

        try:
            virustotal = json.loads(response_data)
        except ValueError as e:
            raise CuckooProcessingError("Unable to convert response to "
                                        "JSON: {0}".format(e))

        if "scans" in virustotal:
            items = virustotal["scans"].items()
            virustotal["scans"] = dict((engine.replace(".", "_"), signature)
                                       for engine, signature in items)

        return virustotal
