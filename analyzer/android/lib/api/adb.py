# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import os
import re
import logging
import subprocess
from droidbot.window import Window
from lib.common.utils import send_file
from droidbot.common import _nd, _nh, _ns, obtainPxPy, obtainVxVy, obtainVwVh

log = logging.getLogger(__name__)

UP = 0
DOWN = 1
DOWN_AND_UP = 2


def install_sample(path):
    """Install the sample on the emulator via adb"""
    log.info("Installing sample in the device: %s", path)
    try:
        args = ["/system/bin/sh", "/system/bin/pm", "install", path]
        output = subprocess.check_output(args)
    except subprocess.CalledProcessError as e:
        log.error("Error installing sample: %r", e)
        return

    log.info("Installed sample: %r", output)

def execute_sample(package, activity):
    """Execute the sample on the emulator via adb"""
    try:
        package_activity = "%s/%s" % (package, activity)
        args = [
            "/system/bin/sh", "/system/bin/am", "start",
            "-n", package_activity,
        ]
        output = subprocess.check_output(args)
    except subprocess.CalledProcessError as e:
        log.error("Error executing package activity: %r", e)
        return

    log.info("Executed package activity: %r", output)

def dump_droidmon_logs(package):
    xposed_logs = "/data/data/de.robv.android.xposed.installer/log/error.log"
    if not os.path.exists(xposed_logs):
        log.info("Could not find any Xposed logs, skipping droidmon logs.")
        return

    tag = "Droidmon-apimonitor-%s" % package
    tag_error = "Droidmon-shell-%s" % package

    log_xposed, log_success, log_error = [], [], []

    for line in open(xposed_logs, "rb"):
        if tag in line:
            log_success.append(line.split(":", 1)[1])

        if tag_error in line:
            log_error.append(line.split(":", 1)[1])

        log_xposed.append(line)

    send_file("logs/xposed.log", "\n".join(log_xposed))
    send_file("logs/droidmon.log", "\n".join(log_success))
    send_file("logs/droidmon_error.log", "\n".join(log_error))

def execute_browser(url):
    """Start URL intent on the emulator."""
    try:
        args = [
            "/system/bin/sh", "/system/bin/am", "start",
            "-a", "android.intent.action.VIEW",
            "-d", url,
        ]
        output = subprocess.check_output(args)
    except subprocess.CalledProcessError as e:
        log.error("Error starting browser intent: %r", e)
        return

    log.info("Intent returned: %r", output)

def take_screenshot(filename):
    try:
        subprocess.check_output(["/system/bin/screencap", "-p",
                                 "/sdcard/%s" % filename])
    except subprocess.CalledProcessError as e:
        log.error("Error creating screenshot: %r", e)
        return

    return "/sdcard/%s" % filename

def shell(command):
    """
    Execute a command
    """
    output = ""
    if isinstance(command, basestring):
        try:
            command = command.encode("utf-8")
        except UnicodeEncodeError:
            pass
    if isinstance(command, list):
        args = command
    elif isinstance(command, str):
        args = command.strip().replace("  ", " ").split(" ")
    else:
        log.error("Error executing command with type: %s", str(type(command)))
        return output
    try:
        output = subprocess.check_output(args)
    except subprocess.CalledProcessError as e:
        pass
    except OSError as e:
        pass

    return output


def getPackagePath(package_name):
    """
    Get installed path of a package
    """
    command = "pm path %s" % package_name
    path = shell(command)
    if path:
        path = path.split(":")[1]
    return path

def getLastInstalledPackagePath():
    """
    Get the last installed package
    It's tricky, should implement a proper way later
    """
    file_name = shell("ls /data/app").splitlines()[-1:][0]
    return "/data/app/%s" % file_name


def getTopActivityName():
    """
    Get current activity
    """
    data = shell("dumpsys activity top").splitlines()
    regex = re.compile("\s*ACTIVITY ([A-Za-z0-9_.]+)/([A-Za-z0-9_.]+)")
    m = regex.search(data[1])
    if m:
        return m.group(1) + "/" + m.group(2)
    return None

def getDisplayInfo():
    displayInfo = getLogicalDisplayInfo()
    if displayInfo:
        return displayInfo
    displayInfo = getPhysicalDisplayInfo()
    if displayInfo:
        return displayInfo
    log.error("Error getting display info")
    return None

def getLogicalDisplayInfo():
    """
    Gets C{mDefaultViewport} and then C{deviceWidth} and C{deviceHeight} values from dumpsys.
    This is a method to obtain display logical dimensions and density
    """
    logicalDisplayRE = re.compile(".*DisplayViewport{valid=true, .*orientation=(?P<orientation>\d+), .*deviceWidth=(?P<width>\d+), deviceHeight=(?P<height>\d+).*")
    for line in shell("dumpsys display").splitlines():
        m = logicalDisplayRE.search(line, 0)
        if m:
            displayInfo = {}
            for prop in ["width", "height", "orientation"]:
                displayInfo[prop] = int(m.group(prop))
            for prop in ["density"]:
                d = getDisplayDensity(None, strip=True, invokeGetPhysicalDisplayIfNotFound=True)
                if d:
                    displayInfo[prop] = d
                else:
                    # No available density information
                    displayInfo[prop] = -1.0
            return displayInfo
    return None

def getPhysicalDisplayInfo():
    """
    Gets C{mPhysicalDisplayInfo} values from dumpsys. This is a method to obtain display dimensions and density
    """
    phyDispRE = re.compile("Physical size: (?P<width>)x(?P<height>).*Physical density: (?P<density>)", re.MULTILINE)
    data = shell("wm size") + shell("wm density")
    m = phyDispRE.search(data)
    if m:
        displayInfo = {}
        for prop in ["width", "height"]:
            displayInfo[prop] = int(m.group(prop))
        for prop in ["density"]:
            displayInfo[prop] = float(m.group(prop))
        return displayInfo
    phyDispRE = re.compile(
        ".*PhysicalDisplayInfo{(?P<width>\d+) x (?P<height>\d+), .*, density (?P<density>[\d.]+).*")
    for line in shell("dumpsys display").splitlines():
        m = phyDispRE.search(line, 0)
        if m:
            displayInfo = {}
            for prop in ["width", "height"]:
                displayInfo[prop] = int(m.group(prop))
            for prop in ["density"]:
                # In mPhysicalDisplayInfo density is already a factor, no need to calculate
                displayInfo[prop] = float(m.group(prop))
            return displayInfo
    # This could also be mSystem or mOverscanScreen
    phyDispRE = re.compile("\s*mUnrestrictedScreen=\((?P<x>\d+),(?P<y>\d+)\) (?P<width>\d+)x(?P<height>\d+)")
    # This is known to work on older versions (i.e. API 10) where mrestrictedScreen is not available
    dispWHRE = re.compile("\s*DisplayWidth=(?P<width>\d+) *DisplayHeight=(?P<height>\d+)")
    for line in shell("dumpsys window").splitlines():
        m = phyDispRE.search(line, 0)
        if not m:
            m = dispWHRE.search(line, 0)
        if m:
            displayInfo = {}
            BASE_DPI = 160.0
            for prop in ["width", "height"]:
                displayInfo[prop] = int(m.group(prop))
            for prop in ["density"]:
                d = 0
                if displayInfo and "density" in displayInfo:
                    d = displayInfo["density"]
                else:
                    _d = shell("getprop ro.sf.lcd_density").strip()
                    if _d:
                        d = float(_d) / BASE_DPI
                    else:
                        _d = shell("getprop qemu.sf.lcd_density").strip()
                        if _d:
                            d = float(_d) / BASE_DPI
                if d:
                    displayInfo[prop] = d
                else:
                    # No available density information
                    displayInfo[prop] = -1.0
            return displayInfo
    return None

def unlock():
    """
    Unlock the screen of the device
    """
    shell("sh /system/bin/input keyevent MENU")
    shell("sh /system/bin/input keyevent BACK")

def press(key):
    """
    Press a key
    """
    shell("sh /system/bin/input keyevent %s" % key)


def getSDKVersion():
    """
    Get version of current SDK
    """
    return int(shell("getprop ro.build.version.sdk"))


def getServiceNames():
    """
    Get current running services
    """
    services = []
    data = shell("dumpsys activity services").splitlines()
    serviceRE = re.compile("^.+ServiceRecord{.+ ([A-Za-z0-9_.]+)/.([A-Za-z0-9_.]+)}")

    for line in data:
        m = serviceRE.search(line)
        if m:
            package = m.group(1)
            service = m.group(2)
            services.append("%s/%s" % (package, service))

    return services

def getFocusedWindow():
    """
    Get the focused window
    """
    for window in getWindows().values():
        if window.focused:
            return window
    return None

def getFocusedWindowName():
    """
    Get the focused window name
    """
    window = getFocusedWindow()
    if window:
        return window.activity
    return None

def getWindows():
    windows = {}
    dww = shell("dumpsys window windows")
    lines = dww.splitlines()
    widRE = re.compile("^ *Window #%s Window{%s (u\d+ )?%s?.*}:" %
                       (_nd("num"), _nh("winId"), _ns("activity", greedy=True)))
    currentFocusRE = re.compile("^  mCurrentFocus=Window{%s .*" % _nh("winId"))
    viewVisibilityRE = re.compile(" mViewVisibility=0x%s " % _nh("visibility"))
    # This is for 4.0.4 API-15
    containingFrameRE = re.compile("^   *mContainingFrame=\[%s,%s\]\[%s,%s\] mParentFrame=\[%s,%s\]\[%s,%s\]" %
                                   (_nd("cx"), _nd("cy"), _nd("cw"), _nd("ch"), _nd("px"), _nd("py"), _nd("pw"),
                                    _nd("ph")))
    contentFrameRE = re.compile("^   *mContentFrame=\[%s,%s\]\[%s,%s\] mVisibleFrame=\[%s,%s\]\[%s,%s\]" %
                                (_nd("x"), _nd("y"), _nd("w"), _nd("h"), _nd("vx"), _nd("vy"), _nd("vx1"),
                                 _nd("vy1")))
    # This is for 4.1 API-16
    framesRE = re.compile("^   *Frames: containing=\[%s,%s\]\[%s,%s\] parent=\[%s,%s\]\[%s,%s\]" %
                          (_nd("cx"), _nd("cy"), _nd("cw"), _nd("ch"), _nd("px"), _nd("py"), _nd("pw"), _nd("ph")))
    contentRE = re.compile("^     *content=\[%s,%s\]\[%s,%s\] visible=\[%s,%s\]\[%s,%s\]" %
                           (_nd("x"), _nd("y"), _nd("w"), _nd("h"), _nd("vx"), _nd("vy"), _nd("vx1"), _nd("vy1")))
    policyVisibilityRE = re.compile("mPolicyVisibility=%s " % _ns("policyVisibility", greedy=True))

    currentFocus = None

    for l in range(len(lines)):
        m = widRE.search(lines[l])
        if m:
            num = int(m.group("num"))
            winId = m.group("winId")
            activity = m.group("activity")
            wvx = 0
            wvy = 0
            wvw = 0
            wvh = 0
            px = 0
            py = 0
            visibility = -1
            policyVisibility = 0x0
            sdkVer = getSDKVersion()

            for l2 in range(l + 1, len(lines)):
                m = widRE.search(lines[l2])
                if m:
                    l += (l2 - 1)
                    break
                m = viewVisibilityRE.search(lines[l2])
                if m:
                    visibility = int(m.group("visibility"))
                if sdkVer >= 17:
                    wvx, wvy = (0, 0)
                    wvw, wvh = (0, 0)
                if sdkVer >= 16:
                    m = framesRE.search(lines[l2])
                    if m:
                        px, py = obtainPxPy(m)
                        m = contentRE.search(lines[l2 + 1])
                        if m:
                            # FIXME: the information provided by 'dumpsys window windows' in 4.2.1 (API 16)
                            # when there's a system dialog may not be correct and causes the View coordinates
                            # be offset by this amount, see
                            # https://github.com/dtmilano/AndroidViewClient/issues/29
                            wvx, wvy = obtainVxVy(m)
                            wvw, wvh = obtainVwVh(m)
                elif sdkVer == 15:
                    m = containingFrameRE.search(lines[l2])
                    if m:
                        px, py = obtainPxPy(m)
                        m = contentFrameRE.search(lines[l2 + 1])
                        if m:
                            wvx, wvy = obtainVxVy(m)
                            wvw, wvh = obtainVwVh(m)
                elif sdkVer == 10:
                    m = containingFrameRE.search(lines[l2])
                    if m:
                        px, py = obtainPxPy(m)
                        m = contentFrameRE.search(lines[l2 + 1])
                        if m:
                            wvx, wvy = obtainVxVy(m)
                            wvw, wvh = obtainVwVh(m)
                else:
                    log.warning("Unsupported Android version %d" % sdkVer)

                # print >> sys.stderr, "Searching policyVisibility in", lines[l2]
                m = policyVisibilityRE.search(lines[l2])
                if m:
                    policyVisibility = 0x0 if m.group("policyVisibility") == "true" else 0x8

            windows[winId] = Window(num, winId, activity, wvx, wvy, wvw, wvh, px, py, visibility + policyVisibility)
        else:
            m = currentFocusRE.search(lines[l])
            if m:
                currentFocus = m.group("winId")

    if currentFocus in windows and windows[currentFocus].visibility == 0:
        windows[currentFocus].focused = True

    return windows


def __transformPointByOrientation((x, y), orientationOrig, orientationDest):
    if orientationOrig != orientationDest:
        if orientationDest == 1:
            _x = x
            x = getDisplayInfo()["width"] - y
            y = _x
        elif orientationDest == 3:
            _x = x
            x = y
            y = getDisplayInfo()["height"] - _x
    return (x, y)

def getOrientation():
    displayInfo = getDisplayInfo()

    if "orientation" in displayInfo:
        return displayInfo["orientation"]

    surfaceOrientationRE = re.compile("SurfaceOrientation:\s+(\d+)")
    output = shell("dumpsys input")
    m = surfaceOrientationRE.search(output)
    if m:
        return int(m.group(1))
    return -1

def touch(x, y, orientation=-1, eventType=DOWN_AND_UP):
    if orientation == -1:
        orientation = getOrientation()
    shell("sh /system/bin/input tap %d %d" % __transformPointByOrientation((x, y), orientation, self.display["orientation"]))

def longTouch(x, y, duration=2000, orientation=-1):
    """
    Long touches at (x, y)
    @param duration: duration in ms
    @param orientation: the orientation (-1: undefined)
    This workaround was suggested by U{HaMi<http://stackoverflow.com/users/2571957/hami>}
    """
    drag((x, y), (x, y), duration, orientation)

def drag((x0, y0), (x1, y1), duration, steps=1, orientation=-1):
    """
    Sends drag event n PX (actually it's using C{input swipe} command.
    @param (x0, y0): starting point in PX
    @param (x1, y1): ending point in PX
    @param duration: duration of the event in ms
    @param steps: number of steps (currently ignored by @{input swipe})
    @param orientation: the orientation (-1: undefined)
    """
    if orientation == -1:
        orientation = getOrientation()
    (x0, y0) = __transformPointByOrientation((x0, y0), orientation, getOrientation())
    (x1, y1) = __transformPointByOrientation((x1, y1), orientation, getOrientation())

    version = getSDKVersion()
    if version <= 15:
        log.error("drag: API <= 15 not supported (version=%d)" % version)
    elif version <= 17:
        shell("sh /system/bin/input swipe %d %d %d %d" % (x0, y0, x1, y1))
    else:
        shell("sh /system/bin/input touchscreen swipe %d %d %d %d %d" % (x0, y0, x1, y1, duration))

def type(text):
    if isinstance(text, str):
        escaped = text.replace("%s", "\\%s")
        encoded = escaped.replace(" ", "%s")
    else:
        encoded = str(text);
    #FIXME find out which characters can be dangerous,
    # for exmaple not worst idea to escape " 
    shell("sh /system/bin/input text %s" % encoded)