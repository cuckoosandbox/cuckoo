# Copyright (C) 2016-2017 Cuckoo Foundation.
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

    Currently obtains IRMA results for the target sample.
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
        if self.options.get("probes"):
            params["probes"] = self.options.get("probes")
        url = urlparse.urljoin(
            self.url, "/api/v1.1/scans/%s/launch" % init.get("id")
        )
        requests.post(url, json=params)

        result = None

        start = time.time()
        while result is None or result.get("status") != self.IRMA_FINISHED_STATUS:
            if start + self.timeout < time.time():
                break

            log.debug("Polling for results for ID %s", init.get("id"))
            url = urlparse.urljoin(
                self.url, "/api/v1.1/scans/%s" % init.get("id")
            )
            result = self._request_json(url)
            time.sleep(1)

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

        """ Fall off if we don't deal with files """
        if self.results.get("info", {}).get("category") != "file":
            log.debug("IRMA supports only file scanning !")
            return {}

        self.url = self.options.get("url")
        self.timeout = int(self.options.get("timeout", 60))
        self.scan = int(self.options.get("scan", 0))
        self.force = int(self.options.get("force", 0))

        sha256 = Files.sha256_file(self.file_path)

        results = self._get_results(sha256)

        if not self.force and not self.scan and not results:
            return {}
        elif self.force or (not results and self.scan):
            log.info("File scan requested: %s", sha256)
            self._scan_file(self.file_path, self.force)
            results = self._get_results(sha256) or {}

        """ FIXME! could use a proper fix here
        that probably needs changes on IRMA side aswell
        --
        related to  https://github.com/elastic/elasticsearch/issues/15377
        entropy value is sometimes 0 and sometimes like  0.10191042566270775
        other issue is that results type changes between string and object :/
        """
        for idx, result in enumerate(results["probe_results"]):
            if result["name"] == "PE Static Analyzer":
                log.debug("Ignoring PE results at index {0}".format(idx))
                results["probe_results"][idx]["results"] = "... scrapped ..."

            """ When VT results comes back with 'detected by 0/58' then it gets
            cached as malicious with signature due to the fact that the result
            exists. This is a workaround to override that tragedy and make it
            compatible with other results.
            """
            if result["name"] == "VirusTotal" \
                    and results["probe_results"][idx]["results"].startswith("detected by 0/"):
                log.debug("Fixing empty match from VT")
                results["probe_results"][idx]["status"] = 0
                results["probe_results"][idx]["results"] = None

        return results
