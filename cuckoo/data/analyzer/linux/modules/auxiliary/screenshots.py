# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import StringIO
from threading import Thread
import time

from lib.api.screenshot import Screenshot
from lib.common.abstracts import Auxiliary
from lib.common.results import NetlogFile

log = logging.getLogger(__name__)

SHOT_DELAY = 1

# Skip the following area when comparing screen shots.
# Example for 800x600 screen resolution.
# SKIP_AREA = ((735, 575), (790, 595))
SKIP_AREA = None

class Screenshots(Thread, Auxiliary):
    """Take screenshots."""

    def start(self):
        log.info("Screenshots started v0.03")
        self.do_take = True

    def __init__(self, options={}, analyzer=None):
        self.do_run = True
        self.initComplete = False
        self.thread = Thread(target = self.run)
        self.thread.start()
        while self.initComplete == False:
            self.thread.join(0.5)

        log.debug("Screenshots init complete")

    def stop(self):
        """Stop screenshotting."""
        log.debug("Screenshots requested stop")
        time.sleep(2) # wait a while to process stuff in the queue
        self.do_run = False
        self.thread.join()
        log.debug("Screenshots stopped")

    def run(self):
        """Run screenshotting.
        @return: operation status.
        """
        self.do_take = False

        scr = Screenshot()

        # TODO We should also send the action "pillow" so that the Web
        # Interface can adequately inform the user about this missing library.
        if not scr.have_pil():
            log.info(
                "Python Image Library (either PIL or Pillow) is not "
                "installed, screenshots are disabled."
            )
            return False

        img_counter = 0
        img_last = None
        self.initComplete = True

        while self.do_run:
            time.sleep(SHOT_DELAY)
            if not self.do_take:
                continue
            try:
                img_current = scr.take()
            except Exception as e:
                log.error("Cannot take screenshot: %s", e)
                continue

            if img_last and scr.equal(img_last, img_current, SKIP_AREA):
                continue

            img_counter += 1

            # workaround as PIL can't write to the socket file object :(
            tmpio = StringIO.StringIO()
            img_current.save(tmpio, format="JPEG")
            tmpio.seek(0)

            # now upload to host from the StringIO
            try:
                nf = NetlogFile("shots/%04d.jpg" % img_counter)

                for chunk in tmpio:
                    nf.sock.sendall(chunk)
            except Exception as e:
                log.debug(str(e),exc_info=True)
            finally:
                if nf:
                    nf.close()

            img_last = img_current

        return True
