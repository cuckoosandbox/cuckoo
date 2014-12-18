# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
#
# Prepare android_on_linux guest Machine:
#
#    Install Ubuntu 12.04
#    Install Linux Dependencies:
#      - sudo add-apt-repository ppa:nilarimogard/webupd8
#      - sudo apt-get update
#      - sudo apt-get install openjdk-7-jre libstdc++6:i386 libgcc1:i386 zlib1g:i386 libncurses5:i386 android-tools-adb android-tools-fastboot
#    Setup The MachineSetup The Machine
#      - Download Android SDK ->  http://developer.android.com/sdk/index.html
#   	- export PATH=$PATH:_path/tool:_path/build-tools/x.x.x.x/
#   	- Create a New AVD of Android  -> https://developer.android.com/tools/devices/index.html
#   	- Start the Android Emulator -> emulator -avd virtual_machine_name
#   	- Copy cuckoo agent (agent.py) Guest Machine
#   	- Start cuckoo's agent.py
#   	- Create Snapshot Named clean_snapshot
#
#
# Powered by:
# Androgurad -> https://code.google.com/p/androguard/
# Google Play Unofficial Python API -> https://github.com/egirault/googleplay-api
#
# Credit to botherder for linux_analyzer_dev -> 	https://github.com/cuckoobox/cuckoo/tree/linux_analyzer_dev
#
# enjoy :-)