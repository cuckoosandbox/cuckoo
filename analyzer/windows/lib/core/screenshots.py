import os
import time
import logging
from threading import Thread

from lib.common.paths import PATHS
from lib.api.screenshot import Screenshot

log = logging.getLogger(__name__)
SHOT_DELAY = 1

class Screenshots(Thread):
    def __init__(self, save_path = PATHS["shots"]):
        Thread.__init__(self)
        self.save_path = save_path
        self.do_run = True

    def stop(self):
        self.do_run = False

    def run(self):
        if not Screenshot().have_pil():
            log.warning("Python Image Library is not installed, screenshots are disabled")
            return False

        img_counter = 0
        img_last = None

        while self.do_run:
            img_current = Screenshot().take()

            if img_last:
                if Screenshot().equal(img_last, img_current):
                    time.sleep(SHOT_DELAY)
                    continue

            img_counter += 1
            save_at = os.path.join(self.save_path, "%s.jpg" % str(img_counter).rjust(4, '0'))
            img_current.save(save_at)

            img_last = img_current
            time.sleep(SHOT_DELAY)

        return True