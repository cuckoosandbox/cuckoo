#!/usr/bin/env bash
# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

#
# This script sets an Android virtual device up to be used for analysis by Cuckoo.
#
# Objectives:
#    1- Downloading and pushing the prebuilt Python interpreter.
#    2- Installing helper APKs.
#    3- Pushing and starting the Cuckoo agent.
#    4- Saving a snapshot of the virtual device.
#
# Prerequisites:
#    1- An Android virtual device needs to be up and running.
#    2- A working setup of cuckoo.
#
# How to use:
#    You need to provide this script with some paths in order for it to work,
#    This can be done by setting a bunch of environment variables via:
#    ```
#    export ADB=<path_to_adb_bin>
#    export CWD=<path_to_cuckoo_working_directory>
#    ```
#    NOTE: for it to work properly (make sure the cwd is initialized).
#    ./init_avd.sh [-s device_serial]
#

usage="
$(basename "$0") [-s device_serial] - Initialize Android virtual devices for Cuckoo analysis.

Options:

  -h  show this help text.
  -s  specify device serial as shown in the output of \`adb devices\`.

Environment variables:

  \$ADB Path to adb binary.
  \$CWD Path to cuckoo working directory.
"
device_tmp="/data/local/tmp"
tmpdir=$(mktemp -d "tmp.XXXX")

# Parse command-line options
while getopts ':hs:' option; do
  case "$option" in
    h) echo "$usage"
      exit
      ;;
    s) device_serial=$OPTARG
      ;;
    :) printf "missing argument for -%s\n" "$OPTARG" >&2
      echo "$usage" >&2
      exit 1
      ;;
   \?) printf "illegal option: -%s\n" "$OPTARG" >&2
      echo "$usage" >&2
      exit 1
      ;;
  esac
done
shift $((OPTIND - 1))

if [ -n "$device_serial" ]; then
  adb_prefix="$ADB -s $device_serial"
else
  adb_prefix="$ADB"
fi

# Checking environment variables.
if [ -z "$CWD" ]; then
  echo 'ERROR: $cwd must be set to the location of your cuckoo working directory.'
  exit 1
else
  if [ ! -f "${CWD}/.cwd" ]; then
    echo "ERROR: incorrect path for cuckoo working directory," \
    "make sure your cwd is both correct and initialized!" >&2
    echo "$usage" >&2
    exit 1
  fi
  echo "Checked cuckoo working directory!"
fi

if [ -z "$ADB" ]; then
  echo 'ERROR: $ADB must be set to the location of adb binary.'
  exit 1
else
  if [ ! -x "$ADB" ]; then
    echo "ERROR: adb command was not found! Make sure you have the" \
    "Android SDK installed with your PATH configured properly." >&2
    echo "$usage" >&2
    exit 1
  fi
  echo "Checked adb binary available!"
fi

# Determine device architecture.
android_abi=$($adb_prefix shell getprop ro.product.cpu.abi)
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
  echo "ERROR: Failed to determine the device's architecture."
  exit 1
fi
echo ""

# Obtain root privileges
$adb_prefix root > /dev/null

# Download and push our prebuilt Python interpreter
echo "Downloading the Python interpreter that matches your device.."
wget -qO- "https://github.com/muhzii/community/raw/master/prebuilt/Python3.7/android-${arch}.tar.gz" | tar xz -C $tmpdir

echo "Pushing Python to the device"
$adb_prefix push "$tmpdir/usr" "$device_tmp"
echo ""

# Push the Cuckoo agent.
echo "Pushing the cuckoo agent"
$adb_prefix push "$CWD/agent/agent.py" "$device_tmp"
$adb_prefix push "$CWD/agent/android-agent.sh" "$device_tmp"
$adb_prefix shell chmod 06755 "$device_tmp/android-agent.sh"
echo ""

# Download & Install the ImportContacts application.
echo "Downloading and installing ImportContacts.apk"
wget -qP "$tmpdir" "https://github.com/cuckoosandbox/cuckoo/raw/master/stuff/android/apps/ImportContacts.apk"
$adb_prefix install "$tmpdir/ImportContacts.apk"
echo ""

# Set SELinux to permissive..
# This is required for frida to work properly on some versions of Android.
# https://github.com/frida/frida-core/tree/master/lib/selinux
$adb_prefix shell setenforce 0

# Start the Cuckoo agent.
echo "Starting the cuckoo agent.."
$adb_prefix shell "$device_tmp/android-agent.sh"
echo ""

# Save a snapshot of the device state.
echo "Taking a snapshot of the virtual device state.."
$adb_prefix emu avd snapshot save cuckoo_snapshot
echo ""

# Remove the temp directory.
rm -rf "$tmpdir"

echo "Device is now ready!"
