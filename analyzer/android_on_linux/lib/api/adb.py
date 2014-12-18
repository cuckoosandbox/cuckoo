# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
from lib.common.exceptions import CuckooPackageError
from lib.common import utils
import os

import re
import string
import subprocess
from zipfile import BadZipfile
from lib.api.androguard import apk

log = logging.getLogger()



def install_sample(path):
    """Install the sample on the emulator via adb"""
    log.info("installing sample on emulator: adb install "+path)
    str=""
    proc = subprocess.Popen(["adb", "install", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for s in proc.stdout.xreadlines():
        str=str+s

    lines = str.split("\n")
    for line in lines:
        #if in command output will appear "Failure" it means that the sample did not install
        if("Failure" in line):
            raise CuckooPackageError("failed to install sample on emulator:"+line)

def get_package_activity_name(path):
    """Using the Android Asset Packaging Tool to extract from apk the package name and main activity
        if it fails try using androgurad to find it"""
    shellcommand = "aapt dump badging " + path
    process = subprocess.Popen(shellcommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    apkInfo = process.communicate()[0].splitlines()
    package=""
    activity=""

    for info in apkInfo:
        #Package info:
        if string.find(info, "package:", 0) != -1:
            package = findBetween(info, "name='", "'")
            continue

        #main activity:
        if string.find(info, "launchable-activity:", 0) != -1:
            activity = findBetween(info, "name='", "'")
            continue

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
    """Using Androguard to extract from apk the package name and main activity"""
    package=""
    main_activity=""

    try :
        a = apk.APK(path)
        if a.is_valid_APK():
            package = a.get_package()
            if package is None:
                raise CuckooPackageError("NO_PACKAGE_NAME_FOUND:"+os.path.basename(path))
            andro_main_activity = a.get_main_activity()
            if andro_main_activity is None:
                activities =  a.get_activities()
                for activity in activities:
                    activity = activity.lower()
                    if ("main" in activity):
                        log.warning('main activity from: if "main" in activity')
                        main_activity=activity
                        break
                    elif ("start" in activity):
                        log.warning('main activity from: if "start" in activity')
                        main_activity=activity
                        break

                if main_activity is "":
                    if activities.__len__()>0:
                        main_activity = activities[0]
                        log.warning("main activity from: activities[0]")
                    else:
                        raise CuckooPackageError("NO_MAIN_ACTIVITY_FOUND:"+os.path.basename(path))
            else:
                main_activity=andro_main_activity
            return package,main_activity
        else:
            raise CuckooPackageError("INVALID_APK:"+os.path.basename(path))

    except (IOError, OSError,BadZipfile) as e:
        raise CuckooPackageError("BAD_APK:"+os.path.basename(path)+","+e.message)

def execute_sample(package,activity):
    """Execute the sample on the emulator via adb"""
    log.info("executing sample on emulator:adb shell am start -n " +package+"/"+activity)
    str=""
    proc = subprocess.Popen(["adb", "shell","am","start","-n", package+"/"+activity], stdout=subprocess.PIPE, stderr=subprocess.PIPE)#adb shell am start -n $pkg/$act
    for s in proc.stdout.xreadlines():
        str=str+s
    lines = str.split("\n")
    for line in lines:
        if("Error" in line):
            #if in command output will appear "Error" it means that the sample did not execute
            raise CuckooPackageError("failed to execute sample on emulator:"+line)

def execute_browser(url):
    """Execute the url on the emulator via adb"""
    str=""
    proc = subprocess.Popen(["adb", "shell","am","start","-a","android.intent.action.VIEW", "-d", url], stdout=subprocess.PIPE)
    for s in proc.stdout.xreadlines():
        log.info(s)
        str=str+s

    lines = str.split("\n")
    for line in lines:
        if("Error" in line):
            #if in command output will appear "Error" it means that the url did not execute
            raise CuckooPackageError("failed to execute default browser on emulator:"+line)

def take_screenshot(img_counter):
    """Take a Screenshot with /system/bin/screencap and pulls it out of the device"""
    filename = "screenshot%s.jpg" % str(img_counter)
    proc1= subprocess.Popen(["adb", "shell","/system/bin/screencap","-p","/sdcard/"+filename], stdout=subprocess.PIPE)
    proc1.communicate()
    proc2=subprocess.Popen(["adb", "pull","/sdcard/"+filename,filename], stdout=subprocess.PIPE)
    proc2.communicate()
    return filename

