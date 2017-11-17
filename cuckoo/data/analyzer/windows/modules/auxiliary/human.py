# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import random
import re
import logging
import threading

from lib.common.abstracts import Auxiliary
from lib.common.defines import (
    KERNEL32, USER32, SHELL32, WM_GETTEXT, WM_GETTEXTLENGTH, BM_CLICK,
    SW_SHOW, WM_SYSCOMMAND, SC_CLOSE, KEYEVENTF_KEYUP, KEYEVENTF_EXTENDEDKEY,
    VK_LMENU, VK_RETURN, VK_RIGHT, VK_TAB, VK_R, WM_CLOSE,
    EnumWindowsProc, EnumChildProc, create_unicode_buffer
)

log = logging.getLogger(__name__)

RESOLUTION = {
    "x": USER32.GetSystemMetrics(0),
    "y": USER32.GetSystemMetrics(1)
}

def foreach_child(hwnd, lparam):
    # List of buttons labels to click.
    buttons = [
        "yes", "oui",
        "ok",
        "i accept",
        "next", "suivant",
        "new", "nouveau",
        "install", "installer",
        "file", "fichier",
        "run", "start", "marrer", "cuter",
        "i agree", "accepte",
        "enable", "activer", "accord", "valider",
        "don't send", "ne pas envoyer",
        "don't save",
        "continue", "continuer",
        "personal", "personnel",
        "scan", "scanner",
        "unzip", "dezip",
        "open", "ouvrir",
        "close the program",
        "execute", "executer",
        "launch", "lancer",
        "save", "sauvegarder",
        "download", "load", "charger",
        "end", "fin", "terminer"
        "later",
        "finish",
        "end",
        "allow access",
        "remind me later",
        "save", "sauvegarder"
    ]

    # List of buttons labels to not click.
    dontclick = [
        "don't run",
        "i do not accept"
    ]

    classname = create_unicode_buffer(50)
    USER32.GetClassNameW(hwnd, classname, 50)

    # Check if the class of the child is button.
    if "button" in classname.value.lower():
        # Get the text of the button.
        length = USER32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0)
        text = create_unicode_buffer(length + 1)
        USER32.SendMessageW(hwnd, WM_GETTEXT, length + 1, text)

        # Check if the button is set as "clickable" and click it.
        textval = text.value.replace("&", "").lower()
        for button in buttons:
            if button in textval:
                for btn in dontclick:
                    if btn in textval:
                        break
                else:
                    log.info("Found button %r, clicking it" % text.value)
                    USER32.SetForegroundWindow(hwnd)
                    KERNEL32.Sleep(1000)
                    USER32.SendMessageW(hwnd, BM_CLICK, 0, 0)

    # Recursively search for childs (USER32.EnumChildWindows).
    return True

# Callback procedure invoked for every enumerated window.
# Purpose is to close any office window
def get_office_window(hwnd, lparam):
    if USER32.IsWindowVisible(hwnd):
        text = create_unicode_buffer(1024)
        USER32.GetWindowTextW(hwnd, text, 1024)
        # TODO Would " - Microsoft (Word|Excel|PowerPoint)$" be better?
        if re.search("- (Microsoft|Word|Excel|PowerPoint)", text.value):
            USER32.SendNotifyMessageW(hwnd, WM_CLOSE, None, None)
            log.info("Closed Office window.")
    return True

# Callback procedure invoked for every enumerated window.
def foreach_window(hwnd, lparam):
    # List of window classes to close if found
    close = [
        "bosa_sdm_microsoft office word 12.0"
    ]

    # List of window classes with specific behaviour
    specific = [
        "ieframe", "#32770"
    ]

    # If the window is visible, enumerate its child objects, looking
    # for buttons.
    if USER32.IsWindowVisible(hwnd):
        classname = create_unicode_buffer(100)
        USER32.GetClassNameW(hwnd, classname, 100)

        if classname.value.strip().lower() in close:
            log.info("Found a window to close: %s" % classname.value.lower())
            USER32.SendMessageW(hwnd, WM_SYSCOMMAND, SC_CLOSE, 0)

        elif classname.value.lower() in specific:
            log.info("Found a window with a specific handler: %s", classname.value.lower())
            handler = getattr(Human, "handle_" + classname.value.replace("#", "").lower())
            if handler:
                handler(hwnd)
            else:
                log.error("No specific handler found for %s", classname.value.lower())

        else:
            USER32.EnumChildWindows(hwnd, EnumChildProc(foreach_child), 0)
    return True

def move_mouse():
    x = random.randint(0, RESOLUTION["x"])
    y = random.randint(0, RESOLUTION["y"])

    # Originally was:
    # USER32.mouse_event(0x8000, x, y, 0, None)
    # Changed to SetCurorPos, since using GetCursorPos would not detect
    # the mouse events. This actually moves the cursor around which might
    # cause some unintended activity on the desktop. We might want to make
    # this featur optional.
    USER32.SetCursorPos(x, y)

def click_mouse():
    # Move mouse to top-middle position.
    USER32.SetCursorPos(RESOLUTION["x"] / 2, 0)
    # Mouse down.
    USER32.mouse_event(2, 0, 0, 0, None)
    KERNEL32.Sleep(50)
    # Mouse up.
    USER32.mouse_event(4, 0, 0, 0, None)

def change_windows():
    # Press ALT
    USER32.keybd_event(VK_LMENU, 0x0, KEYEVENTF_EXTENDEDKEY | 0, 0)
    # Press TAB
    USER32.keybd_event(VK_TAB, 0x0, KEYEVENTF_EXTENDEDKEY | 0, 0)
    # Release TAB
    USER32.keybd_event(VK_TAB, 0x0, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, 0)
    # Release ALT
    USER32.keybd_event(VK_LMENU, 0x0, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, 0)

class Human(threading.Thread, Auxiliary):
    """Human after all"""

    def __init__(self, options={}, analyzer=None):
        threading.Thread.__init__(self)
        Auxiliary.__init__(self, options, analyzer)
        self.do_run = True

    def stop(self):
        self.do_run = False

    def run(self):
        seconds = 0

        # Global disable flag.
        if "human" in self.options:
            self.do_move_mouse = int(self.options["human"])
            self.do_click_mouse = int(self.options["human"])
            self.do_click_buttons = int(self.options["human"])
            self.do_change_windows = int(self.options["human"])
        else:
            self.do_move_mouse = True
            self.do_click_mouse = True
            self.do_click_buttons = True
            self.do_change_windows = True

        # Per-feature enable or disable flag.
        if "human.move_mouse" in self.options:
            self.do_move_mouse = int(self.options["human.move_mouse"])

        if "human.click_mouse" in self.options:
            self.do_click_mouse = int(self.options["human.click_mouse"])

        if "human.click_buttons" in self.options:
            self.do_click_buttons = int(self.options["human.click_buttons"])

        if "human.change_windows" in self.options:
            self.do_change_windows = int(self.options["human.change_windows"])

        if self.do_change_windows:
            # Pick some random procs and spawn them
            spawn = [
                "calc.exe", "notepad.exe", "iexplore.exe", "cmd.exe",
                "explorer.exe", "wmplayer.exe"
            ]
            # Spawn 2 random procs
            hwnd = USER32.GetForegroundWindow()
            for i in xrange(2):
                app = random.choice(spawn)
                log.debug("[HUMAN.CHANGE_WINDOWS] Spawning %s", app)
                SHELL32.ShellExecuteA(hwnd, "open", app, "", "", SW_SHOW)

        while self.do_run:
            if seconds and not seconds % 60:
                USER32.EnumWindows(EnumWindowsProc(get_office_window), 0)

            if self.do_click_mouse:
                click_mouse()

            if self.do_move_mouse:
                move_mouse()

            if self.do_change_windows:
                change_windows()

            if self.do_click_buttons:
                USER32.EnumWindows(EnumWindowsProc(foreach_window), 0)

            KERNEL32.Sleep(1000)
            seconds += 1

    @staticmethod
    def handle_32770(frameHandle):
        """
          Handle IE11's "View Downloads" window
        """
        log.debug("Setting %s as foreground window", frameHandle)
        USER32.SetForegroundWindow(frameHandle)
        # Press RIGHT + ENTER to run the file
        log.debug("Sending RIGHT + ENTER...")
        USER32.keybd_event(VK_RIGHT, 0x4D, KEYEVENTF_EXTENDEDKEY | 0, 0)
        USER32.keybd_event(VK_RIGHT, 0x4D, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, 0)
        USER32.keybd_event(VK_RETURN, 0x1C, KEYEVENTF_EXTENDEDKEY | 0, 0)
        USER32.keybd_event(VK_RETURN, 0x1C, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, 0)

    @staticmethod
    def handle_ieframe(frameHandle):
        """
          Automates the download of a file in IE
        """
        # Get the IE11 download notification toolbar
        hToolbar = USER32.FindWindowExW(frameHandle, 0, u"Frame Notification Bar", 0)
        if not hToolbar:
            log.warn("Download toolbar not found in IEFrame")
            return

        hBar = USER32.FindWindowExW(hToolbar, 0, u"DirectUIHWND", 0)
        if(not hBar or not USER32.IsWindowVisible(hToolbar) or
           not USER32.IsWindowVisible(hBar)):
            # No IE11 download toolbar has been found
            log.warn("Download toolbar not found in IEFrame")
            return

        log.debug("Setting %s window as foreground", frameHandle)
        # Set the IE frame as fg window to receive keys
        USER32.SetForegroundWindow(frameHandle)

        log.debug("Sending ALT + R to IEFrame to run the download")
        USER32.keybd_event(VK_LMENU, 0, KEYEVENTF_EXTENDEDKEY | 0, 0)
        USER32.keybd_event(VK_R, 0, KEYEVENTF_EXTENDEDKEY | 0, 0)
        USER32.keybd_event(VK_R, 0, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, 0)
        USER32.keybd_event(VK_LMENU, 0, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, 0)

