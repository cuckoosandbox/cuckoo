================================
Configuration (Android Analysis)
================================

.. deprecated:: 2.0-rc2
    Android Analysis may not work as expected due to the changes to becoming
    a Cuckoo Package. Proper Android integration will be picked up as a Cuckoo
    update in the future.

To get Cuckoo running Android analysis you should download the
`Android SDK <https://developer.android.com>`_ and extract it in a folder
Cuckoo can access. You should also configure :ref:`avd_conf` with the settings
of your setup.

.. _avd_conf:

avd.conf
========

The main file for Android environment settings is ``$CWD/conf/avd.conf``, it
contains all the generic configuration used to launch the Android emulator and
run the analysis.

The file is largely commented and self-explanatory, but some important options
are as follows:

    * ``emulator_path``:
        The path to the Android emulator (it is located inside Android SDK).

    * ``adb_path``:
        The path to the Android Debug Bridge utility (it is located inside
        Android SDK).

    * ``avd_path``:
        The path where the AVD images are located.
