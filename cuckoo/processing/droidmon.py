# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import json
import logging
import os

from cuckoo.common.abstracts import Processing

log = logging.getLogger(__name__)

class Droidmon(Processing):
    """Extract Dynamic API calls Info From Droidmon logs."""

    def __init__(self):
        self.key = "droidmon"

        self.droidmon = {}

        self.droidmon["crypto_keys"] = []
        self.droidmon["reflection_calls"] = set()
        self.droidmon["SystemProperties"] = set()
        self.droidmon["started_activities"] = []
        self.droidmon["file_accessed"] = set()
        self.droidmon["fingerprint"] = set()
        self.droidmon["registered_receivers"] = set()
        self.droidmon["SharedPreferences"] = []
        self.droidmon["ContentResolver_queries"] = set()
        self.droidmon["ContentValues"] = []
        self.droidmon["encoded_base64"] = []
        self.droidmon["decoded_base64"] = []
        self.droidmon["commands"] = set()
        self.droidmon["commands_output"] = set()
        self.droidmon["ComponentEnabledSetting"] = []
        self.droidmon["data_leak"] = set()
        self.droidmon["events"] = set()
        self.droidmon["crypto_data"] = []
        self.droidmon["mac_data"] = []
        self.droidmon["handleReceiver"] = []
        self.droidmon["sms"] = []
        self.droidmon["killed_process"] = []
        self.droidmon["findResource"] = []
        self.droidmon["findLibrary"] = []
        self.droidmon["loadDex"] = set()
        self.droidmon["TelephonyManager_listen"] = set()
        self.droidmon["registerContentObserver"] = set()
        self.droidmon["accounts"] = set()
        self.droidmon["DexClassLoader"] = []
        self.droidmon["DexFile"] = []
        self.droidmon["PathClassLoader"] = []
        self.droidmon["loadClass"] = set()
        self.droidmon["setMobileDataEnabled"] = set()
        self.droidmon["httpConnections"] = []
        self.droidmon["error"] = []
        self.droidmon["raw"] = []

    def _handle_android_os_SystemProperties_get(self, api_call):
        self.droidmon["SystemProperties"].add(api_call["args"][0])

    def _handle_javax_crypto_spec_SecretKeySpec_javax_crypto_spec_SecretKeySpec(self, api_call):
        key = api_call["args"][0]
        for current_key in self.droidmon["crypto_keys"]:
            if key in current_key["key"]:
                break
        else:
            self.droidmon["crypto_keys"].append({
                "key": api_call["args"][0],
                "type": api_call["args"][1],
            })

    def _handle_javax_crypto_Cipher_doFinal(self, api_call):

        if api_call["this"]["mode"] == 1:
            self.droidmon["crypto_data"].append(api_call["args"][0])
        else:
            self.droidmon["crypto_data"].append(api_call["result"])

    def _handle_java_lang_reflect_Method_invoke(self, api_call):
        reflection = ""
        if "hooked_class" in api_call:
            reflection = api_call["hooked_class"]+"->"+api_call["hooked_method"]
        else:
            reflection = api_call["hooked_method"]
        self.droidmon["reflection_calls"].add(reflection)

    def _handle_dalvik_system_BaseDexClassLoader_findResource(self, api_call):
        self.lib_pairs(api_call, "findResource")

    def _handle_android_app_Activity_startActivity(self, api_call):
        self.droidmon["started_activities"].append(api_call["args"][0])

    def _handle_java_lang_Runtime_exec(self, api_call):
        command = api_call["args"][0]
        if type(command) is list:
            self.droidmon["commands"].add(' '.join(command))
        else:
            self.droidmon["commands"].add(command)

    def _handle_java_lang_ProcessBuilder_start(self, api_call):
        command = api_call["this"]["command"]
        self.droidmon["commands"].add(' '.join(command))

    def _handle_libcore_io_IoBridge_open(self, api_call):
        self.droidmon["file_accessed"].add(api_call["args"][0])

    def _handle_android_app_ActivityThread_handleReceiver(self, api_call):
        self.droidmon["handleReceiver"].append(api_call["args"][0])

    def _handle_android_app_ContextImpl_registerReceiver(self, api_call):
        for arg in api_call["args"]:
            if "mActions" in arg:
                for action in arg["mActions"]:
                    self.droidmon["registered_receivers"].add(action)

    def _handle_android_telephony_TelephonyManager_getDeviceId(self, api_call):
        self.droidmon["fingerprint"].add("getDeviceId")

    def _handle_android_telephony_TelephonyManager_getNetworkOperatorName(self, api_call):
        self.droidmon["fingerprint"].add("getNetworkOperatorName")

    def _handle_android_telephony_TelephonyManager_getSubscriberId(self, api_call):
        self.droidmon["fingerprint"].add("getSubscriberId")

    def _handle_android_telephony_TelephonyManager_getLine1Number(self, api_call):
        self.droidmon["fingerprint"].add("getLine1Number")

    def _handle_android_telephony_TelephonyManager_getNetworkOperator(self, api_call):
        self.droidmon["fingerprint"].add("getNetworkOperator")

    def _handle_android_telephony_TelephonyManager_getSimOperatorName(self, api_call):
        self.droidmon["fingerprint"].add("getSimOperatorName")

    def _handle_android_telephony_TelephonyManager_getSimCountryIso(self, api_call):
        self.droidmon["fingerprint"].add("getSimCountryIso")

    def _handle_android_telephony_TelephonyManager_getSimSerialNumber(self, api_call):
        self.droidmon["fingerprint"].add("getSimSerialNumber")

    def _handle_android_telephony_TelephonyManager_getNetworkCountryIso(self, api_call):
        self.droidmon["fingerprint"].add("getNetworkCountryIso")

    def _handle_android_telephony_TelephonyManager_getDeviceSoftwareVersion(self, api_call):
        self.droidmon["fingerprint"].add("getDeviceSoftwareVersion")

    def _handle_android_net_wifi_WifiInfo_getMacAddress(self, api_call):
        self.droidmon["fingerprint"].add("getMacAddress")

    def _handle_android_app_SharedPreferencesImpl_EditorImpl_putInt(self, api_call):
        self.droidmon["SharedPreferences"].append(self.get_pair(api_call))

    def _handle_android_app_SharedPreferencesImpl_EditorImpl_putString(self, api_call):
        self.droidmon["SharedPreferences"].append(self.get_pair(api_call))

    def _handle_android_app_SharedPreferencesImpl_EditorImpl_putFloat(self, api_call):
        self.droidmon["SharedPreferences"].append(self.get_pair(api_call))

    def _handle_android_app_SharedPreferencesImpl_EditorImpl_putBoolean(self, api_call):
        self.droidmon["SharedPreferences"].append(self.get_pair(api_call))

    def _handle_android_app_SharedPreferencesImpl_EditorImpl_putLong(self, api_call):
        self.droidmon["SharedPreferences"].append(self.get_pair(api_call))

    def _handle_android_content_ContentResolver_query(self, api_call):
        self.droidmon["ContentResolver_queries"].add(api_call["args"][0]["uriString"])

    def _handle_android_content_ContentValues_put(self, api_call):
        self.droidmon["ContentValues"].append(self.get_pair(api_call))

    def _handle_javax_crypto_Mac_doFinal(self, api_call):
        self.droidmon["mac_data"].append(api_call["args"][0])

    def _handle_android_util_Base64_encodeToString(self, api_call):
        self.droidmon["encoded_base64"].append(api_call["args"][0])

    def _handle_android_util_Base64_encode(self, api_call):
        self.droidmon["encoded_base64"].append(api_call["result"][0])

    def _handle_android_app_ApplicationPackageManager_setComponentEnabledSetting(self, api_call):
        states = {
            "0": "COMPONENT_ENABLED_STATE_DEFAULT",
            "1": "COMPONENT_ENABLED_STATE_ENABLED",
            "2": "COMPONENT_ENABLED_STATE_DISABLED",
        }

        component = api_call["args"][0]
        state = api_call["args"][1]

        self.droidmon["ComponentEnabledSetting"].append({
            "component_name": component["mPackage"]+"/"+component["mClass"],
            "component_new_state": states.get(state, ""),
        })

    def _handle_android_location_Location_getLatitude(self, api_call):
        self.droidmon["data_leak"].add("location")

    def _handle_android_location_Location_getLongitude(self, api_call):
        self.droidmon["data_leak"].add("location")

    def _handle_android_app_ApplicationPackageManager_getInstalledPackages(self, api_call):
        self.droidmon["data_leak"].add("getInstalledPackages")

    def _handle_dalvik_system_BaseDexClassLoader_findLibrary(self, api_call):
        self.lib_pairs(api_call, "findLibrary")

    def _handle_android_telephony_SmsManager_sendTextMessage(self, api_call):
        self.droidmon["sms"].append({
            "dest_number": api_call["args"][0],
            "content": " ".join(api_call["args"][1]),
        })

    def _handle_android_util_Base64_decode(self, api_call):
        self.droidmon["decoded_base64"].append(api_call["result"])

    def _handle_android_telephony_TelephonyManager_listen(self, api_call):
        description = {
            1: "LISTEN_SERVICE_STATE",
            16: "LISTEN_CELL_LOCATION",
            32: "LISTEN_CALL_STATE",
            64: "LISTEN_DATA_CONNECTION_STATE",
            256: "LISTEN_SIGNAL_STRENGTHS",
        }

        event = api_call["args"][1]
        if event in description:
            self.droidmon["TelephonyManager_listen"].add(description[event])

    def _handle_android_content_ContentResolver_registerContentObserver(self, api_call):
        self.droidmon["registerContentObserver"].add(api_call["args"][0]["uriString"])

    def _handle_android_content_ContentResolver_insert(self, api_call):
        self.droidmon["ContentResolver_queries"].add(api_call["args"][0]["uriString"])

    def _handle_android_accounts_AccountManager_getAccountsByType(self, api_call):
        self.droidmon["accounts"].add(api_call["args"][0])
        self.droidmon["data_leak"].add("getAccounts")

    def _handle_dalvik_system_BaseDexClassLoader_findResources(self, api_call):
        self.lib_pairs(api_call, "findResource")

    def _handle_android_accounts_AccountManager_getAccounts(self, api_call):
        self.droidmon["data_leak"].add("getAccounts")

    def _handle_android_telephony_SmsManager_sendMultipartTextMessage(self, api_call):
        self.droidmon["sms"].append({
            "dest_number": api_call["args"][0],
            "content": api_call["args"][2],
        })

    def _handle_android_content_ContentResolver_delete(self, api_call):
        self.droidmon["ContentResolver_queries"].add(api_call["args"][0]["uriString"])

    def _handle_android_media_AudioRecord_startRecording(self, api_call):
        self.droidmon["events"].add("mediaRecorder")

    def _handle_android_media_MediaRecorder_start(self, api_call):
        self.droidmon["events"].add("mediaRecorder")

    def _handle_android_content_BroadcastReceiver_abortBroadcast(self, api_call):
        self.droidmon["events"].add("abortBroadcast")

    def _handle_dalvik_system_DexFile_loadDex(self, api_call):
        self.droidmon["loadDex"].add(api_call["args"][0])

    def _handle_dalvik_system_DexClass_dalvik_system_DexClassLoader(self, api_call):
        self.droidmon["DexClassLoader"].append(api_call["args"])

    def _handle_dalvik_system_DexFile_dalvik_system_DexFile(self, api_call):
        self.droidmon["DexFile"].append(api_call["args"])

    def _handle_dalvik_system_PathClassLoader_dalvik_system_PathClassLoader(self, api_call):
        self.droidmon["PathClassLoader"].append(api_call["args"])

    def _handle_android_app_ActivityManager_killBackgroundProcesses(self, api_call):
        self.droidmon["killed_process"].append(api_call["args"][0])

    def _handle_android_os_Process_killProcess(self, api_call):
        self.droidmon["killed_process"].append(api_call["args"][0])

    def _handle_android_net_ConnectivityManager_setMobileDataEnabled(self, api_call):
        self.droidmon["setMobileDataEnabled"].append(api_call["args"][0])

    def _handle_org_apache_http_impl_client_AbstractHttpClient_execute(self, api_call):
        json = {}
        if type(api_call["args"][0]) is dict:
            json["request"] = api_call["args"][1]
        else:
            json["request"] = api_call["args"][0]
        json["response"] = api_call["result"]
        self.droidmon["httpConnections"].append(json)

    def _handle_java_net_URL_openConnection(self, api_call):
        if("file:" in api_call["this"] or "jar:" in api_call["this"]):
            return

        json = {}
        if api_call["result"] != "":
            json["request"] = api_call["result"]["request_method"] + " " + api_call["this"] + " " + api_call["result"]["version"]
            json["response"] = api_call["result"]["version"] + " " + str(api_call["result"]["response_code"]) + " " + api_call["result"]["response_message"]
        else:
            json["request"] = "GET " + api_call["this"] + " HTTP/1.1"
            json["response"] = ""
        self.droidmon["httpConnections"].append(json)

    def _handle_dalvik_system_DexFile_loadClass(self, api_call):
        self.droidmon["loadClass"].add(api_call["args"][0])

    def _handle_java_io_FileOutputStream_write(self, api_call):
        # self.droidmon["command_objects"].append(api_call)
        commands = api_call["buffer"].split('\n')
        for command in commands:
            self.droidmon["commands"].add(command)

    def _handle_java_io_FileInputStream_read(self, api_call):
        pass
        # self.droidmon["command_objects"].append(api_call)
        self.droidmon["commands_output"].add("read: "+api_call["buffer"])

    def get_pair(self, api_call):
        value = None
        if len(api_call["args"]) > 1:
            value = api_call["args"][1]

        return {
            "key": api_call["args"][0],
            "value": value,
        }

    def lib_pairs(self, api_call, key):
        libname = api_call["args"][0]
        for current_key in self.droidmon[key]:
            if libname in current_key["libname"]:
                break
        else:
            self.droidmon[key].append({
                "libname": api_call["args"][0],
                "result": api_call.get("result", ""),
            })

    def keyCleaner(self, d):
        if type(d) is dict:
            for key, value in d.iteritems():
                d[key] = self.keyCleaner(value)
                if '.' in key:
                    d[key.replace('.', '_')] = value
                    del(d[key])
            return d
        if type(d) is list:
            return map(self.keyCleaner, d)
        if type(d) is tuple:
            return tuple(map(self.keyCleaner, d))
        return d

    def run(self):
        """Run extract of printable strings.
        @return: list of printable strings.
        """

        if "file" not in self.task["category"]:
            return {}

        results = {}
        log_path = os.path.join(self.logs_path, "droidmon.log")
        if not os.path.exists(log_path):
            return results

        for line in open(log_path, "rb"):
            try:
                api_call = json.loads(line)
            except Exception:
                self.droidmon["error"].append("Invalid JSON line: %r" % line)
                continue

            self.droidmon["raw"].append(self.keyCleaner(api_call))

            # Construct the function name of the handler for this event.
            api = "_handle_%s_%s" % (api_call["class"], api_call["method"])
            fn = getattr(self, api.replace(".", "_"), None)
            if fn:
                fn(api_call)
            else:
                self.droidmon["error"].append("Unhandled: %r" % line)

        for key, value in self.droidmon.items():
            results[key] = list(value)

        return results
