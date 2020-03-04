# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import random
import logging
from threading import Thread
import time
import subprocess
import os
from Xlib.display import Display
import pyautogui

from lib.common.abstracts import Auxiliary

log = logging.getLogger(__name__)
logging.disable(level=logging.DEBUG)

RESOLUTION = {
    "x": pyautogui.size()[0],
    "y": pyautogui.size()[1]
}

DELAY = 0.5
pyautogui.PAUSE = 1


def move_mouse():
    x = random.randint(0, RESOLUTION["x"])
    y = random.randint(0, RESOLUTION["y"])

    pyautogui.moveTo(x, y, duration=0.25)


def click_mouse():
    x = random.randint(100, RESOLUTION["x"])
    y = random.randint(100, RESOLUTION["y"])

    #pyautogui.click(x, y)
    pyautogui.mouseDown(x,y)
    pyautogui.mouseUp(x,y)


def destroyOfficeWindows(window):
    try:
        children = window.query_tree().children
    except:
        return
    for w in children:
        if w.get_wm_class() in [('libreoffice', 'libreoffice-writer'),
                                #('soffice.bin', 'soffice.bin'),
                                ('libreoffice', 'libreoffice-calc'),
                                ('libreoffice', 'libreoffice-draw'),
                                ('libreoffice', 'libreoffice-impress'),
                                ('win', 'Xpdf')]:
            log.debug("Destroying: %s" % w.get_wm_class()[1])
            w.destroy()
        destroyOfficeWindows(w)


class Human(Thread, Auxiliary):
    """Simulate human."""

    def start(self):
        log.info("Human started v0.02")
        self.do_run = False

    def __init__(self, options={}, analyzer=None):
        self.do_run = True

        Thread.__init__(self)
        Auxiliary.__init__(self, options, analyzer)
        self.initComplete = False
        self.thread = Thread(target = self.run)
        self.thread.start()
        while self.initComplete == False:
            self.thread.join(0.5)

        log.debug("Human init complete")

    def stop(self):
        """Stop Human."""
        log.debug("Human requested stop")
        self.do_run = False
        self.thread.join()
        log.debug("Human stopped")

    def run(self):
        """Run Human.
        @return: operation status.
        """
        seconds = 0
        # Global disable flag.
        if "human" in self.options:
            self.do_move_mouse = int(self.options["human"])
            self.do_click_mouse = int(self.options["human"])
            self.do_click_buttons = int(self.options["human"])
        else:
            self.do_move_mouse = True
            self.do_click_mouse = True
            self.do_click_buttons = True

        # Per-feature enable or disable flag.
        if "human.move_mouse" in self.options:
            self.do_move_mouse = int(self.options["human.move_mouse"])

        if "human.click_mouse" in self.options:
            self.do_click_mouse = int(self.options["human.click_mouse"])

        if "human.click_buttons" in self.options:
            self.do_click_buttons = int(self.options["human.click_buttons"])

        self.initComplete = True

        while self.do_run:
            if seconds and not seconds % 60:
                display = Display()
                root = display.screen().root
                destroyOfficeWindows(root)

            if self.do_click_mouse:
                click_mouse()

            if self.do_move_mouse:
                move_mouse()

            # todo click buttons
            #if self.do_click_buttons:
                #foreach_window

            time.sleep(DELAY)
            seconds += 1

        return True
