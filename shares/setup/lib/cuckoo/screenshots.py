#!/usr/bin/python
# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2011  Claudio "nex" Guarnieri (nex@cuckoobox.org)
# http://www.cuckoobox.org
#
# This file is part of Cuckoo.
#
# Cuckoo is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Cuckoo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.

import os
import sys
import time
from threading import Thread

from cuckoo.logging import *
from cuckoo.paths import *

try:
    import Image
    import ImageGrab
    import ImageChops
    IS_PIL = True
except ImportError, why:
    log("Unable to import Python Image Library: %s." % why, "ERROR")
    IS_PIL = False

SHOT_DELAY = 1

class Screenshots(Thread):
    def __init__(self, save_path = os.path.join(CUCKOO_PATH, "shots")):
        Thread.__init__(self)
        self.save_path = save_path
        self._do_run = True

    def _equal(self, img1, img2):
        return ImageChops.difference(img1, img2).getbbox() is None

    def stop(self):
        self._do_run = False

    def run(self):
        # If PIL is not installed, I abort execution. This is done in order to
        # not have PIL as a forced dependency.
        if not IS_PIL:
            return False

        img_counter = 0
        img_last = None

        log("Started taking screenshots.")

        while self._do_run:
            img_current = ImageGrab.grab()

            if img_last:
                if self._equal(img_last, img_current):
                    time.sleep(SHOT_DELAY)
                    continue

            img_counter += 1
            save_at = os.path.join(self.save_path, "shot_%s.jpg" % img_counter)
            img_current.save(save_at)

            log("Screenshot saved at \"%s\"." % save_at)

            img_last = img_current

            time.sleep(SHOT_DELAY)

        return True
