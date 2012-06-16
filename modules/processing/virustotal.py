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
VIRUSTOTAL_KEY = ""

class VirusTotal(Processing):
    def run(self):
        self.key = "virustotal"
        virustotal = []

        if not os.path.exists(self.file_path):
            raise CuckooProcessingError("File %s not found. Skipping." % self.file_path)

        if not VIRUSTOTAL_KEY:
            raise CuckooProcessingError("API key not configured. Skipping.")

        try:
            md5 = File(self.file_path).get_md5()
        except IOError as e:
            raise CuckooProcessingError("Unable to open %s: %s" % (self.file_path, e.message))
        parameters = {"resource" : md5, "apikey" : VIRUSTOTAL_KEY}
        data = urllib.urlencode(parameters)
        try:
            req = urllib2.Request(VIRUSTOTAL_URL, data)
            response = urllib2.urlopen(req)
        except urllib2.HTTPError as e:
            raise CuckooProcessingError("Error in request to %s: HTTP error code %s" %(VIRUSTOTAL_URL, e.code))
        virustotal = json.loads(response.read())

        return virustotal
