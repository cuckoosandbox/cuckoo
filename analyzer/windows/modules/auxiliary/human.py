#!/usr/bin/env python
# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import random
import logging
from threading import Thread
from ctypes import *

from lib.common.abstracts import Auxiliary
from lib.common.defines import KERNEL32, USER32, WM_GETTEXT, WM_GETTEXTLENGTH, BM_CLICK

log = logging.getLogger(__name__)

EnumWindowsProc = WINFUNCTYPE(c_bool, POINTER(c_int), POINTER(c_int))
EnumChildProc = WINFUNCTYPE(c_bool, POINTER(c_int), POINTER(c_int))

RESOLUTION = {
    "x" : USER32.GetSystemMetrics(0),
    "y" : USER32.GetSystemMetrics(1)
}

def foreach_child(hwnd, lparam):
    buttons = [
        "&yes",
        "&ok",
        "&accept",
        "&next",
        "&install",
        "&run",
        "&agree"
    ]

    classname = create_unicode_buffer(50)
    USER32.GetClassNameW(hwnd, classname, 50)

    # Check if the class of the child is button.
    if classname.value == "Button":
        # Get the text of the button.
        length = USER32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0)
        text = create_unicode_buffer(length + 1)
        USER32.SendMessageW(hwnd, WM_GETTEXT, length + 1, text)

        # Check if the button is "positive".
        for button in buttons:
            if text.value.lower().startswith(button):
                log.info("Found button \"%s\", clicking it" % text.value)
                USER32.SetForegroundWindow(hwnd)
                KERNEL32.Sleep(1000)
                USER32.SendMessageW(hwnd, BM_CLICK, 0, 0)

# Callback procedure invoked for every enumerated window.
def foreach_window(hwnd, lparam):
    # If the window is visible, enumerate its child objects, looking
    # for buttons.
    if USER32.IsWindowVisible(hwnd):
        USER32.EnumChildWindows(hwnd, EnumChildProc(foreach_child), 0)

def move_mouse():
    x = random.randint(0, RESOLUTION["x"])
    y = random.randint(0, RESOLUTION["y"])

    USER32.mouse_event(0x8000, x, y, 0, None)

def click_mouse():
    # mouse down
    USER32.mouse_event(2, 0, 0, 0, None)
    KERNEL32.Sleep(50)
    # mouse up
    USER32.mouse_event(4, 0, 0, 0, None)

class Human(Auxiliary, Thread):
    """Human after all"""

    def __init__(self):
        Thread.__init__(self)
        self.do_run = True

    def stop(self):
        self.do_run = False

    def run(self):
        while self.do_run:
            move_mouse()
            click_mouse()
            USER32.EnumWindows(EnumWindowsProc(foreach_window), 0)
            KERNEL32.Sleep(1000)
