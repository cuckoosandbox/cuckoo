#/usr/bin/env bash

#this script is meant for easy creation on an analysis machine for android emulator avd

#Path to the local installation of the adb - android debug bridge utility.
#ADB=/Applications/adt-bundle/sdk/platform-tools/adb

ADB=$(which adb)

if [ ! -f $ADB ]
then
    echo "Error: adb path is not valid."
    exit
fi
echo "adb has been found."

# First we root the emulator using Superuser
echo "Pushing /system/xbin/su binary"
$ADB remount
$ADB push binaries/su /system/xbin/su
$ADB shell chmod 06755 /system/xbin/su

echo "Installing application Superuser"
$ADB install apps/Superuser.apk

# Install Xposed Application
echo "Installing Xposed Application"
$ADB install apps/de.robv.android.xposed.installer_v33_36570c.apk

# Install Droidmon Application
echo "Installing Droidmon Application"
$ADB install hooking/Droidmon.apk

# Install Anti Emulator Detection Application
echo "Installing Anti Emulator Detection Application"
$ADB install hooking/EmulatorAntiDetect.apk
$ADB push anti-vm/fake-build.prop /data/local/tmp/
$ADB push anti-vm/fake-cpuinfo /data/local/tmp/
$ADB push anti-vm/fake-drivers /data/local/tmp/

# Install Content Generator
echo "Installing Content Generator"
$ADB install apps/ImportContacts.apk

# Install Cuckoo Agent and Python for ARM
echo "Installing Cuckoo Agent and Python for ARM"
$ADB push ../../agent/android/python_agent/ /data/local/
$ADB shell chmod 06755 /data/local/aapt
$ADB shell chmod 06755 /data/local/agent.sh
$ADB shell chmod 06755 /data/local/python/bin/python

echo "Device is ready!"
