================================
Configuration (Android Analysis)
================================

To get Cuckoo running Android analysis you should download the `Android SDK <https://developer.android.com>`_
and extract it in a folder Cuckoo can access.
You should also configure :ref:`avd_conf` with the settings of your setup.

.. _avd_conf:

avd.conf
========

The main file for Android environment settings is *conf/avd.conf*, it contains
all the generic configuration used to launch the Android emulator and run the
analysis.

The file is largely commented and self-explaining, but some of the options you
might want to pay more attention to are:

    * ``emulator_path``: this defines the Android emulator path (it is located inside Android SDK)
    * ``adb_path``: this defines the ADB path (it is located inside Android SDK)
    * ``avd_path``: this defines where AVD images are located
