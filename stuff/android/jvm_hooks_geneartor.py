# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
from collections import OrderedDict

# Android API categories
SERVICE = "services"
BINDER = "binder"
PREFERENCES = "preferences"
CONTENT = "content"
DYNLOAD = "dynload"
PROCESS = "process"
INTENT = "intent"
CRYPTO = "crypto"
REFLECTION = "reflection"
NETWORK = "network"
FILE = "file"


if __name__ == "__main__":
    hooks = []

    def add_hook(class_name, method_name, category):
        hooks.append(OrderedDict([
            ("class", class_name),
            ("method", method_name),
            ("category", category)
        ]))

    # services
    add_hook("android.telephony.TelephonyManager", "getDeviceSoftwareVersion", SERVICE)
    add_hook("android.telephony.TelephonyManager", "getMeid", SERVICE)
    add_hook("android.app.ActivityManager", "getRunningAppProcesses", SERVICE)
    add_hook("android.app.ActivityManager", "getRunningTasks", SERVICE)
    add_hook("android.app.ActivityManager", "getRunningServices", SERVICE)
    add_hook("android.app.ActivityManager", "killBackgroundProcesses", SERVICE)
    add_hook("android.app.usage.UsageStatsManager", "queryUsageStats", SERVICE)
    add_hook("android.accounts.AccountManager", "getAccountsByType", SERVICE)
    add_hook("android.accounts.AccountManager", "getAccounts", SERVICE)
    add_hook("android.media.AudioRecord", "startRecording", SERVICE)
    add_hook("android.media.MediaRecorder", "start", SERVICE)
    add_hook("android.app.ApplicationPackageManager", "getInstalledPackages", SERVICE)
    add_hook("android.app.ApplicationPackageManager", "getInstalledApplications", SERVICE)
    add_hook("android.app.ApplicationPackageManager", "setComponentEnabledSetting", SERVICE)
    add_hook("android.location.Location", "getLatitude", SERVICE)
    add_hook("android.location.Location", "getLongitude", SERVICE)
    add_hook("android.app.NotificationManager", "notify", SERVICE)
    add_hook("android.app.AlarmManager", "setAlarmClock", SERVICE)
    add_hook("android.app.AlarmManager", "set", SERVICE)
    add_hook("android.telephony.SmsManager", "sendDataMessage", SERVICE)
    add_hook("android.telephony.SmsManager", "sendTextMessage", SERVICE)

    # binder
    add_hook("android.telephony.TelephonyManager", "listen", BINDER)
    add_hook("android.app.ContextImpl", "registerReceiver", BINDER)
    add_hook("android.app.ActivityThread", "handleReceiver", BINDER)
    add_hook("android.content.BroadcastReceiver", "abortBroadcast", BINDER)

    # preferences
    add_hook("android.app.SharedPreferencesImpl$EditorImpl", "putFloat", PREFERENCES)
    add_hook("android.app.SharedPreferencesImpl$EditorImpl", "putBoolean", PREFERENCES)
    add_hook("android.app.SharedPreferencesImpl$EditorImpl", "putInt", PREFERENCES)
    add_hook("android.app.SharedPreferencesImpl$EditorImpl", "putLong", PREFERENCES)
    add_hook("android.app.SharedPreferencesImpl$EditorImpl", "putString", PREFERENCES)

    # content
    add_hook("android.content.ContentResolver", "query", CONTENT)
    add_hook("android.content.ContentResolver", "delete", CONTENT)
    add_hook("android.content.ContentResolver", "insert", CONTENT)
    add_hook("android.content.ContentResolver", "registerContentObserver", CONTENT)
    add_hook("android.content.ContentResolver", "registerContentObserver", CONTENT)
    add_hook("android.database.sqlite.SQLiteDatabase", "insert", CONTENT)
    add_hook("android.database.sqlite.SQLiteDatabase", "query", CONTENT)
    add_hook("android.database.sqlite.SQLiteDatabase", "delete", CONTENT)
    add_hook("android.database.sqlite.SQLiteDatabase", "execSQL", CONTENT)

    # dynamic loading
    add_hook("dalvik.system.BaseDexClassLoader", "findResource", DYNLOAD)
    add_hook("dalvik.system.BaseDexClassLoader", "findResources", DYNLOAD)
    add_hook("dalvik.system.BaseDexClassLoader", "findLibrary", DYNLOAD)
    add_hook("dalvik.system.DexFile", "loadClass", DYNLOAD)
    add_hook("java.lang.Runtime", "load", DYNLOAD)
    add_hook("java.lang.Runtime", "loadLibrary", DYNLOAD)
    add_hook("java.lang.Runtime", "exec", DYNLOAD)
    add_hook("dalvik.system.PathClassLoader", "$init", DYNLOAD)
    add_hook("dalvik.system.DexClassLoader", "$init", DYNLOAD)
    add_hook("dalvik.system.DexFile", "loadDex", DYNLOAD)
    add_hook("dalvik.system.InMemoryDexClassLoader", "$init", DYNLOAD)

    # process
    add_hook("android.os.Process", "killProcess", PROCESS)
    add_hook("android.os.Process", "start", PROCESS)
    add_hook("java.lang.ProcessBuilder", "start", PROCESS)
    add_hook("android.os.Debug", "isDebuggerConnected", PROCESS)

    # intent
    add_hook("android.app.Activity", "startActivity", INTENT)
    add_hook("android.app.Activity", "sendBroadcast", INTENT)
    add_hook("android.app.Activity", "startService", INTENT)

    # cryptography
    add_hook("android.util.Base64", "decode", CRYPTO)
    add_hook("android.util.Base64", "encode", CRYPTO)
    add_hook("javax.crypto.spec.SecretKeySpec", "$init", CRYPTO)
    add_hook("javax.crypto.Cipher", "doFinal", CRYPTO)
    add_hook("javax.crypto.Mac", "doFinal", CRYPTO)

    # reflection
    add_hook("java.lang.reflect.Field", "get", REFLECTION)
    add_hook("java.lang.reflect.Field", "set", REFLECTION)
    add_hook("java.lang.reflect.Method", "invoke", REFLECTION)

    # network
    add_hook("sun.net.spi.DefaultProxySelector", "select", NETWORK)

    # file
    add_hook("java.io.FileInputStream", "read", FILE)
    add_hook("java.io.FileOutputStream", "write", FILE)
    add_hook("libcore.io.IoBridge", "open", FILE)

    # write the json configuration file
    with open('jvm_hooks.json', 'w') as f:
        json.dump(hooks, f, indent=4, separators=(',', ': '))
        f.write("\n")
