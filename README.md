Cuckoo Android Extension
=========
Contributed By Check Point Software Technologies LTD.

This is an a extension for Cuckoo Sandbox to Support Android arm Emulator inside
linux virtual machine for executing apk's and url's inside the emulator.

Prepare android_on_linux guest Machine
======================================

- Install Ubuntu 12.04
- Install Linux Dependencies:
      - sudo add-apt-repository ppa:nilarimogard/webupd8
      - sudo apt-get update
      - sudo apt-get install openjdk-7-jre libstdc++6:i386 libgcc1:i386 zlib1g:i386
      libncurses5:i386 android-tools-adb android-tools-fastboot
- Setup The Machine
      - Download Android SDK ->  http://developer.android.com/sdk/index.html
      - export PATH=$PATH:_path/tool:_path/build-tools/x.x.x.x/
      - Create a New AVD of Android  -> https://developer.android.com/tools/devices/index.html
      - Start the Android Emulator -> emulator -avd virtual_machine_name
      - Copy cuckoo agent (agent.py) Guest Machine
      - Start cuckoo's agent.py
      - Create Snapshot Named clean_snapshot

- Recommended AVD Configuration:
      - AVD Name - aosx
      - Device - Nexus One 
      - Target - android 4.1.2
      - Cpu/Abi - arm
      - Ram - 512mb 
      - Vm Heap - 32 
      - Internal Storage - 512mb
      - Sdcard size - 512 mib
      - Emualtion options - use host GPU   


Powered by:
===========
- Androguard -> https://code.google.com/p/androguard/
- Google Play Unofficial Python API -> https://github.com/egirault/googleplay-api

Credit 
======
- botherder for linux_analyzer_dev -> https://github.com/cuckoobox/cuckoo/tree/linux_analyzer_dev

Authors
=======
- Idan Revivo idanr@checkpoint.com
- Ofer Caspi oferc@checkpoint.com
