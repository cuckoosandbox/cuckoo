# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import urllib
import urllib2

from lib.cuckoo.common.objects import File
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError

VIRUSTOTAL_FILE_URL = "https://www.virustotal.com/vtapi/v2/file/report"
VIRUSTOTAL_URL_URL = "https://www.virustotal.com/vtapi/v2/url/report"
VIRUSTOTAL_KEY = "a0283a2c3d55728300d064874239b5346fb991317e8449fe43c902879d758088"

class VirusTotal(Processing):
    """Gets antivirus signatures from VirusTotal.com"""

    def run(self):
        """Runs VirusTotal processing
        @return: full VirusTotal report.
        """
        self.key = "virustotal"
        virustotal = []

        if not VIRUSTOTAL_KEY:
            raise CuckooProcessingError("VirusTotal API key not configured, skip")

        if self.cfg.analysis.category == "file":
            if not os.path.exists(self.file_path):
                raise CuckooProcessingError("File %s not found, skip" % self.file_path)

            resource = File(self.file_path).get_md5()
            url = VIRUSTOTAL_FILE_URL
        elif self.cfg.analysis.category == "url":
            resource = self.cfg.analysis.target
            url = VIRUSTOTAL_URL_URL

        data = urllib.urlencode({"resource" : resource, "apikey" : VIRUSTOTAL_KEY})

        try:
            request = urllib2.Request(url, data)
            response = urllib2.urlopen(request)
            virustotal = json.loads(response.read())
        except urllib2.URLError as e:
            raise CuckooProcessingError("Unable to establish connection to VirusTotal: %s" % e)
        except urllib2.HTTPError as e:
            raise CuckooProcessingError("Unable to perform HTTP request to VirusTotal (http code=%s)" % e.code)

        return virustotal
