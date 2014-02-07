# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import time
import logging
import StringIO
from threading import Thread

from lib.common.abstracts import Auxiliary
from lib.common.results import NetlogFile
from lib.api.screenshot import Screenshot

log = logging.getLogger(__name__)
SHOT_DELAY = 1

class Screenshots(Auxiliary, Thread):
    """Take screenshots."""
    
    def __init__(self):
        Thread.__init__(self)
        self.do_run = True

    def stop(self):
        """Stop screenshotting."""
        self.do_run = False

    def run(self):
        """Run screenshotting.
        @return: operation status.
        """
        if not Screenshot().have_pil():
            log.warning("Python Image Library is not installed, "
                        "screenshots are disabled")
            return False

        img_counter = 0
        img_last = None

        while self.do_run:
            time.sleep(SHOT_DELAY)

            try:
                img_current = Screenshot().take()
            except IOError as e:
                log.error("Cannot take screenshot: %s", e)
                continue

            if img_last:
                if Screenshot().equal(img_last, img_current):
                    continue

            img_counter += 1

            # workaround as PIL can't write to the socket file object :(
            tmpio = StringIO.StringIO()
            img_current.save(tmpio, format="JPEG")
            tmpio.seek(0)

            # now upload to host from the StringIO
            nf = NetlogFile("shots/%s.jpg" % str(img_counter).rjust(4, "0"))
            
            for chunk in tmpio:
                nf.sock.sendall(chunk)
            
            nf.close()

            img_last = img_current

        return True
