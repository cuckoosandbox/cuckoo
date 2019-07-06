#!/usr/bin/env bash
# Copyright (C) 2019 Muhammed Ziad <airomyst517@gmail.com>
# This is a free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License

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
#    1- The `adb` binary needs to be on your PATH
#    2- An Android virtual device needs to be up and running
#
# How to use:
#    You need to provide this script with your cuckoo working directory in order
#    for it to work properly (make sure the cwd is initialized).
#    ./init_avd.sh cwd_path [-s device_serial]
#

usage="$(basename "$0") cwd_path [-s device_serial] - Initialize Android virtual devices for Cuckoo analysis.

where:
    cwd_path  path to the cuckoo working directory.

    -h  show this help text.
    -s  specify device serial as shown in the output of \`adb devices\`."

# Parse command-line options
while getopts ':hs:' option; do
  case "$option" in
    h) echo "$usage"
       exit
       ;;
    s) dev_serial=$OPTARG
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

# Obtain path for the cuckoo working directory
cwd=$(cd $1 > /dev/null; pwd)

# Checking the cuckoo working directory path
if [ ! -f "${cwd}/.cwd" ]
then
    echo "ERROR: incorrect path for cuckoo working directory," \
    "make sure your cwd is both correct and initialized!" >&2
    echo "$usage" >&2
    exit 1
fi
echo "Checked cuckoo working directory!"

# Checking the adb binary
ADB=$(which adb)
if [ ! -f $ADB ]
then
    echo "ERROR: adb command was not found! Make sure you have the" \
    "Android SDK installed with your PATH configured properly.." >&2
    echo "$usage" >&2
    exit 1
fi
echo "Checked adb binary available!"
echo

if [ ! -z $dev_serial ]
then
    ADB="${ADB} -s ${dev_serial}"
fi

device_tmp="/data/local/tmp"

# Determine the device architecture
abi=$($ADB shell getprop ro.product.cpu.abi)

all_archs=("arm64" "arm" "x86_64" "x86")
for i in ${all_archs[@]}
do
    if [[ $abi == *"${i}"* ]]
    then
      arch=$i
      break
    fi
done

# Obtain root privileges
$ADB root > /dev/null

# Download and push our prebuilt Python interpreter
tmp_dir=$(mktemp -d "tmp.XXXX")
echo "Downloading the Python interpreter that matches your device.."
wget -qO- "https://github.com/muhzii/community/raw/master/prebuilt/Python3.7/${arch}-android.tar.gz" | tar xz -C $tmp_dir

echo "Pushing Python to the device"
$ADB push "${tmp_dir}/usr" $device_tmp
echo

# Push the Cuckoo agent.
echo "Pushing the cuckoo agent"
$ADB push "${cwd}/agent/agent.py" $device_tmp
$ADB push "${cwd}/agent/android-agent.sh" $device_tmp
$ADB shell chmod 06755 "${device_tmp}/android-agent.sh"
echo

# Download & Install the ImportContacts application.
echo "Downloading and installing ImportContacts.apk"
wget -qP $tmp_dir "https://github.com/cuckoosandbox/cuckoo/raw/master/stuff/android/apps/ImportContacts.apk"
$ADB install "${tmp_dir}/ImportContacts.apk"
echo

# Set SELinux to permissive..
# This is required for frida to work properly on some versions of Android.
# https://github.com/frida/frida-core/tree/master/lib/selinux
$ADB shell setenforce 0

# Start the Cuckoo agent.
echo "Starting the cuckoo agent.."
$ADB shell "${device_tmp}/android-agent.sh"
echo

# Save a snapshot of the device state.
echo "Taking a snapshot of the virtual device state.."
$ADB emu avd snapshot save cuckoo_snapshot
echo

# Remove unneeded stuff!
rm -rf $tmp_dir

echo "Device is now ready!"
