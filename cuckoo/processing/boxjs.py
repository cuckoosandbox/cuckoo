# Based on the Irma processing plugin for Cuckoo, which is licensed GPLv3.
# See https://github.com/cuckoosandbox/cuckoo/blob/master/docs/LICENSE for the license text.

import logging
import time
import urlparse
import requests
import json

from cuckoo.common.abstracts import Processing
from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.common.files import Files
from cuckoo.common.config import config


log = logging.getLogger(__name__)

class BoxJS(Processing):

    def _request_text(self, url, **kwargs):
        """Wrapper around doing a request and parsing its text output."""
        try:
            r = requests.get(url, timeout=self.timeout, **kwargs)
            return r.text if r.status_code == 200 else {}
        except (requests.ConnectionError, ValueError) as e:
            raise CuckooOperationalError(
                "Unable to GET results: %r" % e.message
            )

    def request_json(self, url, **kwargs):
        """Wrapper around doing a request and parsing its JSON output."""
        try:
            log.debug(str(url))
            r = requests.get(url, timeout=self.timeout, **kwargs)
            return r.json() if r.status_code == 200 and r.text else {}
        except (requests.ConnectionError, ValueError) as e:
            raise CuckooOperationalError(
                "Unable to GET results: %r" % e.message
            )
    def request_json(self, IOC, **kwargs):
        """Wrapper around doing a request and parsing its JSON output."""
        try:
            log.debug(str(IOC))
            r = requests.get(IOC, timeout=self.timeout, **kwargs)
            return r.json() if r.status_code == 200 and r.text else {}
        except (requests.ConnectionError, ValueError) as e:
            raise CuckooOperationalError(
                "Unable to GET results: %r" % e.message
            )


    def _post_text(self, url, **kwargs):
        """Wrapper around doing a post and parsing its text output."""
        try:
	    flags = {"flags": kwargs.get("flags", "")}
	    # log.debug(kwargs)
            # log.debug("FLAGS %s" % flags)
	    files = {"sample": kwargs.get("sample")}
            r = requests.post(url, timeout=self.timeout, data=flags, files=files)
            return r.text if r.status_code == 200 else {}
        except (requests.ConnectionError, ValueError) as e:
            raise CuckooOperationalError(
                "Unable to POST to the API server: %r" % e.message
            )

    def _post_json(self, url, **kwargs):
        """Wrapper around doing a post and parsing its JSON output."""
        try:
            r = requests.post(url, timeout=self.timeout, **kwargs)
            return r.json() if r.status_code == 200 else {}
        except (requests.ConnectionError, ValueError) as e:
            raise CuckooOperationalError(
                "Unable to POST to the API server: %r" % e.message
            )

    def run(self):
        self.key = "boxjs"

        """ Fall off if we don't deal with files """
        if self.results.get("info", {}).get("category") != "file":
            log.debug("Box-js supports only file scanning!")
            return {}

        self.url = self.options.get("url")
        self.timeout = int(self.options.get("timeout", 60))
	self.ioc = self.options.get("IOC")

        # Post file for scanning.
        # files = {
        #     "sample": open(self.file_path, "rb"),
        # }
        postUrl = urlparse.urljoin(self.url, "/sample")
        analysis_id = self._post_text(postUrl, sample=open(self.file_path, "rb")) # returns a UUID
        base_url = "{}/sample/{}".format(self.url, str(analysis_id))

        flags = ""

        # Wait for the analysis to be completed.
        done = False
        while not done:
            time.sleep(1)
            result = self.request_json(base_url)
            code = result["code"]
            retry = False

            # Read the status code, and retry with different flags if necessary
            if code == 0: # Success
                done = True
            elif code == 1: # Generic error
                # We don't know how to handle this, so continue
                done = True
                # Todo: show result["stderr"] to the user?
            elif code == 2: # Timeout
                # Todo: choose whether to use longer timeout
                done = True
            elif code == 3: # Rewrite error
                flags += "--no-rewrite "
                retry = True
            elif code == 4: # Syntax error
                # Todo: implement JSE decoding if necessary
                done = True
            elif code == 5: # Retry with --no-shell-error
                flags += "--no-shell-error "
                retry = True
            else:
                raise CuckooOperationalError("Unknown error code: %s" % code)

            if retry:
                postUrl = urlparse.urljoin(self.url, "/sample")
                analysis_id = self._post_text(postUrl,  sample=open(self.file_path, "rb"), flags=flags)# returns a UUID
                base_url = "{}/sample/{}".format(self.url, str(analysis_id))

        # Fetch the results.
        results = {}
        urls_url = "{}/urls".format(base_url)
        resources_url = "{}/resources".format(base_url)
	iocs_ioc = "{}/IOC".format(base_url)
        results["urls"] = self.request_json(urls_url)
        results["resources"] = self.request_json(resources_url)
	results["IOC"] = self.request_json(iocs_ioc)

        # Delete the results.
        try:
            requests.delete(base_url, timeout=self.timeout)
        except (requests.ConnectionError, ValueError) as e:
            raise CuckooOperationalError(
                "Unable to send a DELETE request: %r" % e.message
            )

        return results

