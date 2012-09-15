#!/usr/bin/env python
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ctypes
import logging
from threading import Thread

from lib.common.abstracts import Auxiliary

log = logging.getLogger(__name__)

EnumChildWindows = ctypes.windll.user32.EnumChildWindows
EnumWindows = ctypes.windll.user32.EnumWindows
EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int))
EnumChildProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int))
GetClassName = ctypes.windll.user32.GetClassNameW
#GetWindowText = ctypes.windll.user32.GetWindowTextW
#GetWindowTextLength = ctypes.windll.user32.GetWindowTextLengthW
IsWindowVisible = ctypes.windll.user32.IsWindowVisible
SendMessage = ctypes.windll.user32.SendMessageW

WM_GETTEXT = 0x0D
WM_GETTEXTLENGTH = 0x0E
WM_COMMAND = 0x0111
BM_CLICK = 0x00F5

def foreach_child(hwnd, lParam):
    buff = ctypes.create_unicode_buffer(50)
    GetClassName(hwnd, buff, 50)

    if buff.value == "Button":
        length = SendMessage(hwnd, WM_GETTEXTLENGTH, 0, 0)
        text = ctypes.create_unicode_buffer(length + 1)
        SendMessage(hwnd, WM_GETTEXT, length + 1, text)

        if text.value.lower() == "&yes" or \
           text.value.lower() == "&ok" or \
           text.value.lower().startswith("&next"):
            log.info("Found button \"%s\", clicking it" % text.value)
            ctypes.windll.kernel32.Sleep(1000)
            SendMessage(hwnd, BM_CLICK, 0, 0)

def foreach_window(hwnd, lParam):
    if IsWindowVisible(hwnd):
        #length = GetWindowTextLength(hwnd)
        #buff = ctypes.create_unicode_buffer(length + 1)
        #GetWindowText(hwnd, buff, length + 1)
        #log.info("Found Window with title: %s" % buff.value)

        EnumChildWindows(hwnd, EnumChildProc(foreach_child), 0)

    return True

class Human(Auxiliary, Thread):
    def __init__(self):
        Thread.__init__(self)
        self.do_run = True

    def stop(self):
        self.do_run = False

    def run(self):
        while self.do_run:
            EnumWindows(EnumWindowsProc(foreach_window), 0)
            ctypes.windll.kernel32.Sleep(1000)
