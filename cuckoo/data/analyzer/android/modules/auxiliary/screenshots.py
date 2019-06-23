# Copyright (C) 2014-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import os
import time
import tempfile
import logging
import threading

from lib.api.screenshot import Screenshot
from lib.common.abstracts import Auxiliary
from lib.common.results import upload_to_host
from lib.common.exceptions import CuckooScreenshotError

log = logging.getLogger(__name__)

SHOT_DELAY = 1

class Screenshots(threading.Thread, Auxiliary):
    """Take screenshots."""

    def __init__(self, options={}):
        threading.Thread.__init__(self)
        Auxiliary.__init__(self, options)
        self.do_run = True

    def stop(self):
        """Stop screenshotting."""
        self.do_run = False
        self.join()

    def run(self):
        """Run screenshotting.
        @return: operation status.
        """
        scr = Screenshot()

        img_count = 0
        img_last = None
        img_current = tempfile.mktemp()

        while self.do_run:
            time.sleep(SHOT_DELAY)

            try:
                scr.take(img_current)
            except CuckooScreenshotError as e:
                log.error("Error taking screenshot: %s", e)
                continue

            if img_last and scr.equal(img_last, img_current):
                continue

            upload_to_host(img_current, "shots/%s.png" % img_count)
            os.unlink(img_last)

            img_count += 1            
            img_last = img_current
            img_current = tempfile.mktemp()

        return True
