# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import string
import subprocess
import zipfile

from lib.api.androguard import apk
from lib.common.exceptions import CuckooPackageError
from lib.common.utils import send_file

log = logging.getLogger(__name__)

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

def get_package_activity_name(path):
    """Using the Android Asset Packaging Tool to extract from apk the package name and main activity"""
    shellcommand = "/data/local/aapt dump badging " + path
    str = os.popen(shellcommand).read()
    apkInfo = str.splitlines()
    # process = subprocess.Popen(shellcommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    # apkInfo = process.communicate()[0].splitlines()
    package = ""
    activity = ""

    for info in apkInfo:
        # Package info:
        if string.find(info, "package:", 0) != -1:
            package = findBetween(info, "name='", "'")
            continue

        # main activity:
        if string.find(info, "launchable-activity:", 0) != -1:
            activity = findBetween(info, "name='", "'")
            continue

    log.info("package=%s,activity=%s", package, activity)

    if(activity.__eq__("") or package.__eq__("")):
        return get_package_activity_name_androguard(path)
    return package, activity

def findBetween(s, prefix, suffix):
    try:
        start = s.index(prefix) + len(prefix)
        end = s.index(suffix, start)
        return s[start:end]
    except ValueError:
        return ""

def get_package_activity_name_androguard(path):
    """Using - Androguard to extract from apk the package name and main activity"""
    package = ""
    main_activity = ""

    try:
        a = apk.APK(path)
        if a.is_valid_APK():
            package = a.get_package()
            if package is None:
                raise CuckooPackageError("NO_PACKAGE_NAME_FOUND:"+os.path.basename(path))
            andro_main_activity = a.get_main_activity()
            if andro_main_activity is None:
                activities = a.get_activities()
                for activity in activities:
                    activity = activity.lower()
                    if "main" in activity:
                        log.warning('main activity from: if "main" in activity')
                        main_activity = activity
                        break
                    elif "start" in activity:
                        log.warning('main activity from: if "start" in activity')
                        main_activity = activity
                        break

                if not main_activity:
                    if activities:
                        main_activity = activities[0]
                        log.warning("main activity from: activities[0]")
                    else:
                        raise CuckooPackageError("NO_MAIN_ACTIVITY_FOUND:"+os.path.basename(path))
            else:
                main_activity = andro_main_activity
            return package, main_activity
        else:
            raise CuckooPackageError("INVALID_APK:"+os.path.basename(path))
    except (IOError, OSError, zipfile.BadZipfile) as e:
        raise CuckooPackageError("BAD_APK:"+os.path.basename(path)+","+e.message)

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
