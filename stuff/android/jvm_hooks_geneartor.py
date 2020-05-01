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
GENERIC = "generic"


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
    add_hook("android.content.pm.PackageInstaller", "uninstall", SERVICE)
    add_hook("android.app.ApplicationPackageManager", "getInstalledApplications", SERVICE)
    add_hook("android.app.ApplicationPackageManager", "setComponentEnabledSetting", SERVICE)
    add_hook("android.location.Location", "getLatitude", SERVICE)
    add_hook("android.location.Location", "getLongitude", SERVICE)
    add_hook("android.app.NotificationManager", "notify", SERVICE)
    add_hook("android.app.AlarmManager", "setAlarmClock", SERVICE)
    add_hook("android.app.AlarmManager", "set", SERVICE)
    add_hook("android.app.AlarmManager", "setRepeating", SERVICE)
    add_hook("android.telephony.SmsManager", "sendDataMessage", SERVICE)
    add_hook("android.telephony.SmsManager", "sendTextMessage", SERVICE)
    add_hook("android.os.PowerManager", "newWakeLock", SERVICE)
    add_hook("android.app.ContextImpl", "getSystemService", SERVICE)
    add_hook("android.os.PowerManager$WakeLock", "acquire", SERVICE)

    # binder
    add_hook("android.telephony.TelephonyManager", "listen", BINDER)
    add_hook("android.content.ContextWrapper", "bindService", BINDER)

    # preferences
    add_hook("android.app.SharedPreferencesImpl", "contains", PREFERENCES)
    add_hook("android.app.SharedPreferencesImpl", "getInt", PREFERENCES)
    add_hook("android.app.SharedPreferencesImpl", "getFloat", PREFERENCES)
    add_hook("android.app.SharedPreferencesImpl", "getLong", PREFERENCES)
    add_hook("android.app.SharedPreferencesImpl", "getBoolean", PREFERENCES)
    add_hook("android.app.SharedPreferencesImpl", "getString", PREFERENCES)
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
    add_hook("android.database.sqlite.SQLiteDatabase", "update", CONTENT)
    add_hook("android.database.sqlite.SQLiteDatabase", "openDatabase", CONTENT)
    add_hook("android.content.ContentValues", "put", CONTENT)
    add_hook("android.provider.Settings$Secure", "getString", CONTENT)
    add_hook("android.provider.Settings$Global", "getString", CONTENT)
    add_hook("android.provider.Settings$Global", "getInt", CONTENT)
    add_hook("android.content.res.AssetManager", "open", CONTENT)
    add_hook("android.content.ClipboardManager", "getPrimaryClip", CONTENT)
    add_hook("android.content.ClipboardManager", "setPrimaryClip", CONTENT)
    add_hook("android.hardware.camera2.CameraManager", "openCamera", CONTENT)
    add_hook("android.os.Environment", "getExternalStorageDirectory", CONTENT)
    add_hook("android.os.Environment", "getExternalStorageState", CONTENT)

    # dynamic loading
    add_hook("dalvik.system.BaseDexClassLoader", "findResource", DYNLOAD)
    add_hook("dalvik.system.BaseDexClassLoader", "findResources", DYNLOAD)
    add_hook("dalvik.system.BaseDexClassLoader", "findLibrary", DYNLOAD)
    add_hook("dalvik.system.DexFile", "loadClass", DYNLOAD)
    add_hook("java.lang.Runtime", "load", DYNLOAD)
    add_hook("java.lang.Runtime", "loadLibrary", DYNLOAD)
    add_hook("java.lang.Runtime", "exec", DYNLOAD)
    add_hook("dalvik.system.DexFile", "loadDex", DYNLOAD)
    add_hook("dalvik.system.DexFile", "loadClass", DYNLOAD)
    add_hook("dalvik.system.DexFile", "$init", DYNLOAD)
    add_hook("dalvik.system.DexFile", "openDexFile", DYNLOAD)

    # process
    add_hook("android.os.Process", "killProcess", PROCESS)
    add_hook("android.os.Process", "start", PROCESS)
    add_hook("java.lang.ProcessBuilder", "start", PROCESS)
    add_hook("android.os.Debug", "isDebuggerConnected", PROCESS)
    add_hook("android.util.Log", "d", PROCESS)
    add_hook("android.util.Log", "e", PROCESS)
    add_hook("java.util.concurrent.ScheduledExecutorService", "scheduleAtFixedRate", PROCESS)
    add_hook("java.util.concurrent.ExecutorService", "invokeAll", PROCESS)

    # intent
    add_hook("android.app.Activity", "startActivity", INTENT)
    add_hook("android.app.Activity", "sendBroadcast", INTENT)
    add_hook("android.app.Activity", "startService", INTENT)
    add_hook("android.app.ContextImpl", "startService", INTENT)
    add_hook("android.app.ContextImpl", "registerReceiver", INTENT)
    add_hook("android.app.ActivityThread", "handleReceiver", INTENT)
    add_hook("android.content.BroadcastReceiver", "abortBroadcast", INTENT)
    add_hook("android.content.ContextWrapper", "startService", INTENT)
    add_hook("android.content.ContextWrapper", "startActivity", INTENT)
    add_hook("android.content.ContextWrapper", "sendBroadcast", INTENT)
    add_hook("android.content.ContextWrapper", "startActivities", INTENT)
    add_hook("android.content.Intent", "$init", INTENT)
    add_hook("android.content.Intent", "setAction", INTENT)

    # cryptography
    add_hook("android.util.Base64", "decode", CRYPTO)
    add_hook("android.util.Base64", "encode", CRYPTO)
    add_hook("javax.crypto.Cipher", "doFinal", CRYPTO)
    add_hook("javax.crypto.Cipher", "update", CRYPTO)
    add_hook("javax.crypto.Cipher", "getInstance", CRYPTO)
    add_hook("javax.crypto.Cipher", "init", CRYPTO)
    add_hook("javax.crypto.Mac", "doFinal", CRYPTO)
    add_hook("javax.crypto.Mac", "update", CRYPTO)
    add_hook("javax.crypto.Mac", "getInstance", CRYPTO)
    add_hook("javax.crypto.Mac", "init", CRYPTO)
    add_hook("java.security.MessageDigest", "digest", CRYPTO)
    add_hook("java.security.MessageDigest", "update", CRYPTO)
    add_hook("java.security.SecureRandom", "setSeed", CRYPTO)

    # reflection
    add_hook("java.lang.reflect.Field", "get", REFLECTION)
    add_hook("java.lang.reflect.Field", "set", REFLECTION)
    add_hook("java.lang.reflect.Method", "invoke", REFLECTION)

    # network
    add_hook("sun.net.spi.DefaultProxySelector", "select", NETWORK)
    add_hook("android.webkit.WebView", "addJavascriptInterface", NETWORK)
    add_hook("android.webkit.WebView", "setWebChromeClient", NETWORK)
    add_hook("android.webkit.WebView", "setWebViewClient", NETWORK)
    add_hook("android.webkit.WebView", "loadUrl", NETWORK)
    add_hook("android.webkit.WebView", "loadData", NETWORK)
    add_hook("android.webkit.WebView", "loadDataWithBaseURL", NETWORK)
    add_hook("android.webkit.WebView", "evaluateJavascript", NETWORK)
    add_hook("android.webkit.WebView", "postUrl", NETWORK)
    add_hook("android.webkit.WebView", "postWebMessage", NETWORK)
    add_hook("android.webkit.WebView", "setHttpAuthUsernamePassword", NETWORK)
    add_hook("android.webkit.WebView", "getHttpAuthUsernamePassword", NETWORK)
    add_hook("android.webkit.WebViewDatabase", "getHttpAuthUsernamePassword", NETWORK)
    add_hook("android.webkit.WebViewDatabase", "setHttpAuthUsernamePassword", NETWORK)

    # generic
    add_hook("android.view.Window", "setFlags", GENERIC)
    add_hook("android.view.Window", "addFlags", GENERIC)
    add_hook("android.view.SurfaceView", "setSecure", GENERIC)

    # write the json configuration file
    with open('jvm_hooks.json', 'w') as f:
        json.dump(hooks, f, indent=4, separators=(',', ': '))
        f.write("\n")
