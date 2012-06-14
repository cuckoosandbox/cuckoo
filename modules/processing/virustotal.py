# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import urllib
import urllib2

from lib.cuckoo.common.utils import File
from lib.cuckoo.common.abstracts import Processing

VIRUSTOTAL_URL = "https://www.virustotal.com/vtapi/v2/file/report"
VIRUSTOTAL_KEY = ""

class VirusTotal(Processing):
    def run(self):
        self.key = "virustotal"
        virustotal = []

        if not os.path.exists(self.file_path):
            return virustotal

        md5 = File(self.file_path).get_md5()
        parameters = {"resource" : md5, "apikey" : VIRUSTOTAL_KEY}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(VIRUSTOTAL_URL, data)
        response = urllib2.urlopen(req)
        virustotal = json.loads(response.read())

        return virustotal
