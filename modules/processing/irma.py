# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import json

try:
    import requests
    HAVE_REQUESTS = True

    # Disable requests/urllib3 debug & info messages.
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
except ImportError:
    HAVE_REQUESTS = False

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.common.utils import sha256_file

log = logging.getLogger(__name__)

class Irma(Processing):
    """Gets antivirus signatures from IRMA for various results.

    Currently obtains IRMA results for the target sample or URL and the
    dropped files.
    """
    order = 2

    IRMA_FILE_RESULT = "%s/api/v1.1/files/%s"
    IRMA_SCAN_RESULT = "%s/api/v1.1/results/%s"

    def _get_file_url(self, url, sha256):
        return self.IRMA_FILE_RESULT % (url, sha256)

    def _get_scan_url(self, url, scan_id):
        return self.IRMA_SCAN_RESULT % (url, scan_id)

    def _request_json(self, url, **kwargs):
        """Wrapper around doing a request and parsing its JSON output."""
        if not HAVE_REQUESTS:
            raise CuckooOperationalError(
                "The IRMA processing module requires the requests "
                "library (install with `pip install requests`)")

        try:
            r = requests.get(url, timeout=self.timeout, **kwargs)
            return r.json() if r.status_code == 200 else {}
        except (requests.ConnectionError, ValueError) as e:
            raise CuckooOperationalError("Unable to fetch VirusTotal "
                                         "results: %r" % e.message)

    def run(self):
        """Runs IRMA processing
        @return: full IRMA report.
        """
        self.key = "irma"

        self.url = self.options.get("url")
        self.timeout = int(self.options.get("timeout", 60))
        self.scan = int(self.options.get("scan", 0))

        fresults = self._request_json(self._get_file_url(self.url, sha256_file(self.file_path)))
        if fresults["items"][0]["result_id"]:
            results = self._request_json(self._get_scan_url(self.url, fresults["items"][0]["result_id"]))
        else:
            results = "{}"

        return results
