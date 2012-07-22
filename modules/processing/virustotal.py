# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import urllib
import urllib2

from lib.cuckoo.common.utils import File
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError

VIRUSTOTAL_URL = "https://www.virustotal.com/vtapi/v2/file/report"
VIRUSTOTAL_KEY = "a"

class VirusTotal(Processing):
    """Gets antivirus signatures from VirusTotal.com"""

    def run(self):
        """Runs VirusTotal processing
        @return: full VirusTotal report.
        """

        self.key = "virustotal"
        virustotal = []

        if not os.path.exists(self.file_path):
            raise CuckooProcessingError("File %s not found, skip" % self.file_path)

        if not VIRUSTOTAL_KEY:
            raise CuckooProcessingError("VirusTotal API key not configured, skip")

        try:
            md5 = File(self.file_path).get_md5()
        except IOError as e:
            raise CuckooProcessingError("Unable to open \"%s\": %s" % (self.file_path, e.message))

        data = urllib.urlencode({"resource" : md5, "apikey" : VIRUSTOTAL_KEY})

        try:
            req = urllib2.Request(VIRUSTOTAL_URL, data)
            response = urllib2.urlopen(req)
            virustotal = json.loads(response.read())
        except urllib2.URLError as e:
            raise CuckooProcessingError("Unable to establish connection to VirusTotal: %s" % e)
        except urllib2.HTTPError as e:
            raise CuckooProcessingError("Unable to perform HTTP request to VirusTotal (http code=%s)" % e.code)

        return virustotal
