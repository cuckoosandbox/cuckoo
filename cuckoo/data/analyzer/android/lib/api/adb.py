# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import logging
import os
import subprocess

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
