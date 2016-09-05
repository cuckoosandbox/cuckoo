# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import time
import urlparse
import requests

from cuckoo.common.abstracts import Processing
from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.common.files import Files

log = logging.getLogger(__name__)

class Irma(Processing):
    """Gets antivirus signatures from IRMA for various results.

    Currently obtains IRMA results for the target sample or URL and the
    dropped files.
    """
    # IRMA statuses https://github.com/quarkslab/irma-cli/blob/master/irma/apiclient.py
    IRMA_FINISHED_STATUS = 50

    def _request_json(self, url, **kwargs):
        """Wrapper around doing a request and parsing its JSON output."""
        try:
            r = requests.get(url, timeout=self.timeout, **kwargs)
            return r.json() if r.status_code == 200 else {}
        except (requests.ConnectionError, ValueError) as e:
            raise CuckooOperationalError(
                "Unable to fetch IRMA results: %r" % e.message
            )

    def _post_json(self, url, **kwargs):
        """Wrapper around doing a post and parsing its JSON output."""
        try:
            r = requests.post(url, timeout=self.timeout, **kwargs)
            return r.json() if r.status_code == 200 else {}
        except (requests.ConnectionError, ValueError) as e:
            raise CuckooOperationalError(
                "Unable to fetch IRMA results: %r" % e.message
            )

    def _scan_file(self, filepath, force):
        # Initialize scan in IRMA.
        init = self._post_json(urlparse.urljoin(self.url, "/api/v1.1/scans"))

        log.debug("Scanning file: %s", filepath)

        # Post file for scanning.
        files = {
            "files": open(filepath, "rb"),
        }
        url = urlparse.urljoin(
            self.url, "/api/v1.1/scans/%s/files" % init.get("id")
        )
        self._post_json(url, files=files,)

        # launch posted file scan
        params = {
            "force": force,
        }
        url = urlparse.urljoin(
            self.url, "/api/v1.1/scans/%s/launch" % init.get("id")
        )
        requests.post(url, json=params)

        result = None

        while result is None or result.get("status") != self.IRMA_FINISHED_STATUS:
            log.debug("Polling for results for ID %s", init.get("id"))
            url = urlparse.urljoin(
                self.url, "/api/v1.1/scans/%s" % init.get("id")
            )
            result = self._request_json(url)
            time.sleep(1)

        return

    def _get_results(self, sha256):
        # Fetch list of scan IDs.
        results = self._request_json(
            urlparse.urljoin(self.url, "/api/v1.1/files/%s" % sha256)
        )

        if not results.get("items"):
            log.info("File %s hasn't been scanned before", sha256)
            return

        result_id = results["items"][-1]["result_id"]
        return self._request_json(
            urlparse.urljoin(self.url, "/api/v1.1/results/%s" % result_id)
        )

    def run(self):
        """Runs IRMA processing
        @return: full IRMA report.
        """
        self.key = "irma"

        self.url = self.options.get("url")
        self.timeout = int(self.options.get("timeout", 60))
        self.scan = int(self.options.get("scan", 0))
        self.force = int(self.options.get("force", 0))

        sha256 = Files.sha256_file(self.file_path)

        results = self._get_results(sha256)

        if self.force or (not results and self.scan):
            log.info("File scan requested: %s", sha256)
            self._scan_file(self.file_path, self.force)
            return self._get_results(sha256) or {}

        return results
