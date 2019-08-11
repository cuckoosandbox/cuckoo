#!/usr/bin/env bash
# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

#
# This script sets an Android virtual device up to be used for analysis by Cuckoo.
#
# Objectives:
#    1- Creating an Android virtual device.
#    2- Downloading and pushing our prebuilt Python interpreter.
#    3- Installing helper APKs.
#    4- Pushing and starting the Cuckoo agent.
#    5- Saving a snapshot of the virtual device state.
#
# How to use:
#    You need to provide this script with some paths via setting shell variables:
#    ```
#    export ANDROID_SDK_ROOT=<path_to_android_sdk>
#    export CWD=<path_to_cuckoo_working_directory>
#    ```
#    NOTE: for it to work properly, make sure the cwd is initialized.
#

usage="
$(basename "$0") - Initialize Android virtual devices for Cuckoo analysis.

Options:

  -h  show this help text.

Environment variables:

  \$ANDROID_SDK_ROOT Path to Android SDK folder.
  \$CWD Path to cuckoo working directory.
"
device_tmp="/data/local/tmp"
cd "$(dirname $0)"

# Parse command-line options
while getopts ":h" option; do
  case "$option" in
    h) 
      echo "$usage"
      exit
      ;;
    \?) 
      echo "illegal option: -$OPTARG" >&2
      echo "$usage" >&2
      exit 1
      ;;
  esac
done
shift $((OPTIND - 1))

# Check environment variables.
if [ -z "$CWD" ]; then
  echo "ERROR: \$CWD must be set to the location of your cuckoo working" \
  "directory." >&2
  exit 1
else
  if [ ! -f "$CWD/.cwd" ]; then
    echo "ERROR: incorrect path for cuckoo working directory," \
    "make sure your cwd is both correct and initialized." >&2
    echo "$usage" >&2
    exit 1
  fi
  echo "Checked cuckoo working directory!"
fi

if [ -z "$ANDROID_SDK_ROOT" ]; then
  echo "ERROR: \$ANDROID_SDK_ROOT must be set to the location of the Android" \
  "SDK root folder." >&2
  exit 1
else
  if [ ! -f "$ANDROID_SDK_ROOT/platform-tools/source.properties" ] ||
     [ ! -f "$ANDROID_SDK_ROOT/tools/source.properties" ] ||
     [ ! -f "$ANDROID_SDK_ROOT/emulator/source.properties" ] ||
     [ ! -d "$ANDROID_SDK_ROOT/skins" ]; then
    echo "ERROR: The Android SDK is not installed properly! Make sure" \
    "you have the latest SDK installed with your ANDROID_SDK_ROOT" \
    "pointing to the root folder." >&2
    echo "$usage" >&2
    exit 1
  fi
  echo "Checked the Android SDK!"
  echo ""
fi

avdmanager="$ANDROID_SDK_ROOT/tools/bin/avdmanager"
sdkmanager="$ANDROID_SDK_ROOT/tools/bin/sdkmanager"
emulator="$ANDROID_SDK_ROOT/emulator/emulator"
adb="$ANDROID_SDK_ROOT/platform-tools/adb"
hardware_skins="$($avdmanager list device | grep id: | grep -oe '".*"' | tr -d '"')"

# Gather the virtual device specs from user input.
read -ep "Specify the label of the virtual device: " device_label
read -ep "Specify size of sdcard in megabytes: " sdcard_size
read -ep "Specify the Android ABI [x86, x86_64, armeabi-v7a, arm64-v8a]: " android_abi
case "$android_abi" in
  x86|x86_64|armeabi-v7a|arm64-v8a)
    ;;
  *)
    echo "ERROR: Incorrect input for Android ABI." >&2
    exit 1
    ;;
esac
read -ep "Specify the Android API level [>= 21]: " android_api_level
if [ "$android_api_level" -lt 21 ]; then
  echo "ERROR: Unsupported Android version. Select an API level" \
  "higher than 21 (Lollipop)." >&2
  exit 1
fi
read -ep "Select the hardware definition of the device [${hardware_skins//$'\n'/, }] (default: pixel): " hardware_def
for i in $hardware_skins; do
  case "$hardware_def" in
    "$i")
      is_valid_skin_id=yes
      break
      ;;
  esac
done
if [ -z "$is_valid_skin_id" ]; then
  if [ -z "$hardware_def" ]; then
    hardware_def="pixel"
  else
    echo "ERROR: invalid choice for device hardware definition." >&2
    exit 1
  fi
fi
image_pkg_name="system-images;android-$android_api_level;default;$android_abi"
echo ""

# Create the virtual device..
echo "Creating the Android virtual device.."
$sdkmanager --install "$image_pkg_name"
if [ ! $? -eq 0 ]; then
  echo "ERROR: sdkmanager failed to locate package." >&2
  exit 1
fi
$avdmanager create avd -n "$device_label" -c "$sdcard_size"M -k "$image_pkg_name" -d "$hardware_def"
if [ ! $? -eq 0 ]; then
  exit 1
else
  echo "Virtual device created successfully!"
  echo ""
fi

# Start the Android emulator.
echo "Starting the Android emulator.."
$emulator @"$device_label" >/dev/null 2>&1 &
until [ -n "$emulator_label" ]; do
  avail_emulators=$($adb devices | grep -oe "emulator-[0-9]*")
  for i in $avail_emulators; do
    avd_name=$($adb -s "$i" emu avd name)
    if [ -n "$(echo "$avd_name" | grep "$device_label")" ]; then
      emulator_label="$i"
      break
    fi
  done
done
adb+=" -s $emulator_label"

echo "Waiting for the device to become available.."
until [ "$($adb get-state 2>/dev/null)" == "device" ]; do
  sleep 1
done
echo ""

# Obtain root privileges through adbd.
$adb root >/dev/null
if [ ! $? -eq 0 ]; then
  echo "ERROR: failed to obtain root privileges, command: \`$adb root\`." >&2
  exit 1
fi

# Determine the device architecture.
supported_archs="arm64 arm x86_64 x86"
for i in $supported_archs; do
  case "$android_abi" in
    *"$i"*)
      arch="$i"
      break
      ;;
  esac
done
if [ -z "$arch" ]; then
  echo "ERROR: failed to determine device architecture from" \
  "the Android ABI: $android_abi" >&2
  exit 1
fi

# Download and push our prebuilt Python interpreter
echo "Downloading the prebuilt Python interpreter for your device.."
wget -qO- "https://github.com/muhzii/community/raw/master/prebuilt/Python3.7/android-${arch}.tar.gz" | tar xz -C .

echo "Pushing Python to the device"
$adb push usr/ "$device_tmp"
rm -rf usr/
echo ""

# Push the Cuckoo agent.
echo "Pushing the cuckoo agent"
$adb push "$CWD/agent/agent.py" "$device_tmp"
$adb push "$CWD/agent/android-agent.sh" "$device_tmp"
$adb shell chmod 06755 "$device_tmp/android-agent.sh"
echo ""

# Download & Install the ImportContacts application.
echo "Downloading and installing ImportContacts.apk"
wget -qP "$tmpdir" "https://github.com/cuckoosandbox/cuckoo/raw/master/stuff/android/apps/ImportContacts.apk"
$adb install "$tmpdir/ImportContacts.apk"
echo ""

# Set SELinux to permissive..
# This is required for frida to work properly on some versions of Android.
# https://github.com/frida/frida-core/tree/master/lib/selinux
$adb shell setenforce 0

# Start the Cuckoo agent.
echo "Starting the cuckoo agent.."
$adb shell "$device_tmp/android-agent.sh"
echo ""

# Save a snapshot of the device state.
echo "Taking a snapshot of the virtual device state.."
$adb emu avd snapshot save cuckoo_snapshot
echo ""

echo "Device is now ready!"
