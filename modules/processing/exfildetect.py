# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# Copyright (C) 2016-2017 Nils Rogmann
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import requests
import time
import json

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.exceptions import CuckooProcessingError

log = logging.getLogger(__name__)

class ExfilDetect(Processing):
    """Gets analysis results from exfildetect.com.

    Currently obtains data exfiltration analysis results for the generated pcap file.
    """
    order = 2

    def run(self):
        """Runs ExfilDetect processing
        @return: ExfilDetect analysis results.
        """
        self.key = "exfildetect"


        apikey = self.options.get("apikey")
	url = self.options.get("url")
	self.retries = int(self.options.get("retries", 5))

        if not apikey:
            raise CuckooProcessingError("ExfilDetect API key not "
                                        "configured, skipping Exfildetect "
                                        "processing module.")
        if not url:
            raise CuckooProcessingError("ExfilDetect url not "
                                        "configured, skipping Exfildetect "
                                        "processing module.")

        if not self.pcap_path:
            raise CuckooProcessingError("ExfilDetect pcap file not found, "
                                        "skipping Exfildetect "
                                        "processing module.")

        self.submit_url = url + "/index.php?page=submit"
        self.query_url = url + "/index.php?page=analyses"

        submit_answer = self.send_file(self.submit_url, apikey, self.pcap_path)

        query = ""
        if "Hash" in submit_answer.text:
             query = submit_answer.text.split(' ')[-1]

             for i in range(1, self.retries+1):
                 time.sleep(5)
                 query_answer = self.get_results(self.query_url, apikey, query)

                 if "No data" in query_answer.text or "No results" in query_answer.text:
                     time.sleep(5*i)
                 else:
                     break

        else:
             log.debug("Submission error")
             return {}

        if "No data" in query_answer.text or "No results" in query_answer.text:
            return {}

        results = {"results":json.loads(query_answer.text),"hash":query}
	return results

    def send_file(self, url, key, file_path):

        post_data = {"apikey": key}
        post_file =  {"userfile": open(file_path, "rb")}

        answer = requests.post(url, timeout=60, data=post_data, files=post_file, verify=True)

        return answer

    def get_results(self, url, key, query):

        post_data = {"apikey": key, "query": query}
        answer = requests.post(url, timeout=60, data=post_data, verify=True)

        return answer

