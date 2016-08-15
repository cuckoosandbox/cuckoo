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
    IRMA_FILE_RESULT = "{0}/api/v1.1/files/{1}"
    IRMA_SCAN_RESULT = "{0}/api/v1.1/results/{1}"

    IRMA_SCAN_INIT = "{0}/api/v1.1/scans"
    IRMA_SCAN_NEW = "{0}/api/v1.1/scans/{1}/files"
    IRMA_SCAN_LAUNCH = "{0}/api/v1.1/scans/{1}/launch"

    def _get_file_url(self, url, sha256):
        return self.IRMA_FILE_RESULT.format(url, sha256)

    def _get_scan_url(self, url, scan_id):
        return self.IRMA_SCAN_RESULT.format(url, scan_id)

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
            raise CuckooOperationalError("Unable to fetch IRMA "
                                         "results: %r" % e.message)

    def _post_json(self, url, **kwargs):
        """Wrapper around doing a post and parsing its JSON output."""
        if not HAVE_REQUESTS:
            raise CuckooOperationalError(
                "The IRMA processing module requires the requests "
                "library (install with `pip install requests`)")

        try:
            r = requests.post(url, timeout=self.timeout, **kwargs)
            return json.loads(r.text) if r.status_code == 200 else {}
        except (requests.ConnectionError, ValueError) as e:
            raise CuckooOperationalError("Unable to fetch IRMA "
                                         "results: %r" % e.message)

    def _scan_file(self, url, filepath, force):
        # init scan in IRMA
        init = self._post_json(self.IRMA_SCAN_INIT.format(url))
        log.debug("returned from IRMA : {0}".format(init))

        # post file for scanning
        files = { "files": open(filepath, "rb") }
        log.debug("PROCESSING : {0}".format(filepath))
        r = self._post_json(self.IRMA_SCAN_NEW.format(url, init.get("id")), files=files)
        log.debug("returned from IRMA : {0}".format(r))

        # launch posted file scan
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        params = { 'force': force }
        
        log.debug("LAUNCH : {0}".format(self.IRMA_SCAN_LAUNCH.format(url, init.get("id"))))
        r = requests.post(self.IRMA_SCAN_LAUNCH.format(url, init.get("id")), data=json.dumps(params), headers=headers)
        result = json.loads(r.text)
        log.debug("returned from IRMA : {0}".format(result))

    def run(self):
        """Runs IRMA processing
        @return: full IRMA report.
        """
        self.key = "irma"

        self.url = self.options.get("url")
        self.timeout = int(self.options.get("timeout", 60))
        self.scan = int(self.options.get("scan", 0))
        self.force = int(self.options.get("force", 0))

        sha256 = sha256_file(self.file_path)

        if self.scan:
             log.debug("File scan requested : {0}".format(sha256))
             self._scan_file(self.url, self.file_path, self.force)

        fresults = self._request_json(self._get_file_url(self.url, sha256))
        log.debug("File Scans : {0}".format(fresults))

        if not fresults:
            log.info("File {0} is unknown for your IRMA setup".format(sha256))

        if fresults["items"][0]["result_id"]:
            results = self._request_json(self._get_scan_url(self.url, fresults["items"][0]["result_id"]))
            log.debug("File Scan Result : {0}".format(results))
        else:
            results = "{}"

        return results
