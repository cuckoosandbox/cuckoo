import json
import logging
import os
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError

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
        self.droidmon["mac_data"]=[]
        self.droidmon["handleReceiver"]=[]
        self.droidmon["sms"]=[]
        self.droidmon["killed_process"]=[]
        self.droidmon["findResource"]=[]
        self.droidmon["findLibrary"]=[]
        self.droidmon["loadDex"]=set()
        self.droidmon["TelephonyManager_listen"]=set()
        self.droidmon["registerContentObserver"]=set()
        self.droidmon["accounts"]=set()
        self.droidmon["DexClassLoader"]=[]
        self.droidmon["DexFile"]=[]
        self.droidmon["PathClassLoader"]=[]
        self.droidmon["loadClass"]=set()
        self.droidmon["setMobileDataEnabled"]=set()
        self.droidmon["httpConnections"]=[]
        self.droidmon["error"]=[]
        self.droidmon["raw"]=[]

        self.log_hook_method_map = {}
        self.log_hook_method_map["android.os.SystemProperties_get"] = self.android_os_SystemProperties_get
        self.log_hook_method_map["javax.crypto.spec.SecretKeySpec_javax.crypto.spec.SecretKeySpec"] = self.javax_crypto_spec_SecretKeySpec_javax_crypto_spec_SecretKeySpec
        self.log_hook_method_map["javax.crypto.Cipher_doFinal"] = self.javax_crypto_Cipher_doFinal
        self.log_hook_method_map["java.lang.reflect.Method_invoke"] = self.java_lang_reflect_Method_invoke
        self.log_hook_method_map["dalvik.system.BaseDexClassLoader_findResource"] = self.dalvik_system_BaseDexClassLoader_findResource
        self.log_hook_method_map["android.app.Activity_startActivity"] = self.android_app_Activity_startActivity
        self.log_hook_method_map["java.lang.Runtime_exec"] = self.java_lang_Runtime_exec
        self.log_hook_method_map["java.lang.ProcessBuilder_start"] = self.java_lang_ProcessBuilder_start
        self.log_hook_method_map["libcore.io.IoBridge_open"] = self.libcore_io_IoBridge_open
        self.log_hook_method_map["android.app.ActivityThread_handleReceiver"] = self.android_app_ActivityThread_handleReceiver
        self.log_hook_method_map["android.app.ContextImpl_registerReceiver"] = self.android_app_ContextImpl_registerReceiver
        self.log_hook_method_map["android.telephony.TelephonyManager_getDeviceId"] = self.android_telephony_TelephonyManager_getDeviceId
        self.log_hook_method_map["android.telephony.TelephonyManager_getNetworkOperatorName"] = self.android_telephony_TelephonyManager_getNetworkOperatorName
        self.log_hook_method_map["android.telephony.TelephonyManager_getSubscriberId"] = self.android_telephony_TelephonyManager_getSubscriberId
        self.log_hook_method_map["android.telephony.TelephonyManager_getLine1Number"] = self.android_telephony_TelephonyManager_getLine1Number
        self.log_hook_method_map["android.telephony.TelephonyManager_getNetworkOperator"] = self.android_telephony_TelephonyManager_getNetworkOperator
        self.log_hook_method_map["android.telephony.TelephonyManager_getSimOperatorName"] = self.android_telephony_TelephonyManager_getSimOperatorName
        self.log_hook_method_map["android.telephony.TelephonyManager_getSimCountryIso"] = self.android_telephony_TelephonyManager_getSimCountryIso
        self.log_hook_method_map["android.telephony.TelephonyManager_getSimSerialNumber"] = self.android_telephony_TelephonyManager_getSimSerialNumber
        self.log_hook_method_map["android.telephony.TelephonyManager_getNetworkCountryIso"] = self.android_telephony_TelephonyManager_getNetworkCountryIso
        self.log_hook_method_map["android.telephony.TelephonyManager_getDeviceSoftwareVersion"] = self.android_telephony_TelephonyManager_getDeviceSoftwareVersion
        self.log_hook_method_map["android.net.wifi.WifiInfo_getMacAddress"] = self.android_net_wifi_WifiInfo_getMacAddress
        self.log_hook_method_map["android.app.SharedPreferencesImpl$EditorImpl_putInt"] = self.android_app_SharedPreferencesImpl_EditorImpl_putInt
        self.log_hook_method_map["android.app.SharedPreferencesImpl$EditorImpl_putString"] = self.android_app_SharedPreferencesImpl_EditorImpl_putString
        self.log_hook_method_map["android.app.SharedPreferencesImpl$EditorImpl_putFloat"] = self.android_app_SharedPreferencesImpl_EditorImpl_putFloat
        self.log_hook_method_map["android.app.SharedPreferencesImpl$EditorImpl_putBoolean"] = self.android_app_SharedPreferencesImpl_EditorImpl_putBoolean
        self.log_hook_method_map["android.app.SharedPreferencesImpl$EditorImpl_putLong"] = self.android_app_SharedPreferencesImpl_EditorImpl_putLong
        self.log_hook_method_map["android.content.ContentResolver_query"] = self.android_content_ContentResolver_query
        self.log_hook_method_map["android.telephony.TelephonyManager_getSubscriberId"] = self.android_telephony_TelephonyManager_getSubscriberId
        self.log_hook_method_map["android.content.ContentValues_put"] = self.android_content_ContentValues_put
        self.log_hook_method_map["android.telephony.TelephonyManager_getNetworkCountryIso"] = self.android_telephony_TelephonyManager_getNetworkCountryIso
        self.log_hook_method_map["javax.crypto.Mac_doFinal"] = self.javax_crypto_Mac_doFinal
        self.log_hook_method_map["android.util.Base64_encodeToString"] = self.android_util_Base64_encodeToString
        self.log_hook_method_map["android.util.Base64_encode"] = self.android_util_Base64_encode
        self.log_hook_method_map["android.app.ApplicationPackageManager_setComponentEnabledSetting"] = self.android_app_ApplicationPackageManager_setComponentEnabledSetting
        self.log_hook_method_map["android.location.Location_getLatitude"] = self.android_location_Location_getLatitude
        self.log_hook_method_map["android.location.Location_getLongitude"] = self.android_location_Location_getLongitude
        self.log_hook_method_map["android.app.ApplicationPackageManager_getInstalledPackages"] = self.android_app_ApplicationPackageManager_getInstalledPackages
        self.log_hook_method_map["dalvik.system.BaseDexClassLoader_findLibrary"] = self.dalvik_system_BaseDexClassLoader_findLibrary
        self.log_hook_method_map["android.telephony.SmsManager_sendTextMessage"] = self.android_telephony_SmsManager_sendTextMessage
        self.log_hook_method_map["android.util.Base64_decode"] = self.android_util_Base64_decode
        self.log_hook_method_map["android.telephony.TelephonyManager_listen"] = self.android_telephony_TelephonyManager_listen
        self.log_hook_method_map["android.content.ContentResolver_registerContentObserver"] = self.android_content_ContentResolver_registerContentObserver
        self.log_hook_method_map["android.content.ContentResolver_insert"] = self.android_content_ContentResolver_insert
        self.log_hook_method_map["android.accounts.AccountManager_getAccountsByType"] = self.android_accounts_AccountManager_getAccountsByType
        self.log_hook_method_map["dalvik.system.BaseDexClassLoader_findResources"] = self.dalvik_system_BaseDexClassLoader_findResources
        self.log_hook_method_map["android.accounts.AccountManager_getAccounts"] = self.android_accounts_AccountManager_getAccounts
        self.log_hook_method_map["android.telephony.SmsManager_sendMultipartTextMessage"] = self.android_telephony_SmsManager_sendMultipartTextMessage
        self.log_hook_method_map["android.content.ContentResolver_delete"] = self.android_content_ContentResolver_delete
        self.log_hook_method_map["android.media.AudioRecord_startRecording"] = self.android_media_AudioRecord_startRecording
        self.log_hook_method_map["android.media.MediaRecorder_start"] = self.android_media_MediaRecorder_start
        self.log_hook_method_map["android.content.BroadcastReceiver_abortBroadcast"] = self.android_content_BroadcastReceiver_abortBroadcast
        self.log_hook_method_map["dalvik.system.DexFile_loadDex"] = self.dalvik_system_DexFile_loadDex
        self.log_hook_method_map["dalvik.system.DexClass.dalvik.system_DexClassLoader"] = self.dalvik_system_DexClass_dalvik_system_DexClassLoader
        self.log_hook_method_map["dalvik.system.DexFile.dalvik.system_DexFile"] = self.dalvik_system_DexFile_dalvik_system_DexFile
        self.log_hook_method_map["dalvik.system.PathClassLoader.dalvik.system_PathClassLoader"] = self.dalvik_system_PathClassLoader_dalvik_system_PathClassLoader
        self.log_hook_method_map["android.app.ActivityManager_killBackgroundProcesses"] = self.android_app_ActivityManager_killBackgroundProcesses
        self.log_hook_method_map["android.os.Process_killProcess"] = self.android_os_Process_killProcess
        self.log_hook_method_map["android.net.ConnectivityManager_setMobileDataEnabled"] = self.android_net_ConnectivityManager_setMobileDataEnabled
        self.log_hook_method_map["org.apache.http.impl.client.AbstractHttpClient_execute"] = self.org_apache_http_impl_client_AbstractHttpClient_execute
        self.log_hook_method_map["java.net.URL_openConnection"] = self.java_net_URL_openConnection
        self.log_hook_method_map["dalvik.system.DexFile.loadClass"] = self.dalvik_system_DexFile_loadClass
        self.log_hook_method_map["java.io.FileInputStream_read"] = self.java_io_FileInputStream_read
        self.log_hook_method_map["java.io.FileOutputStream_write"] = self.java_io_FileOutputStream_write

    def android_os_SystemProperties_get(self, api_call):
        self.droidmon["SystemProperties"].add(api_call["args"][0])

    def javax_crypto_spec_SecretKeySpec_javax_crypto_spec_SecretKeySpec(self,api_call):
        key = api_call["args"][0]
        exists=False
        for current_key in self.droidmon["crypto_keys"]:
            if key in current_key["key"]:
                exists=True
                break
        if not exists:
            new_key = {}
            new_key["key"]=api_call["args"][0]
            new_key["type"]=api_call["args"][1]
            self.droidmon["crypto_keys"].append(new_key)

    def javax_crypto_Cipher_doFinal(self,api_call):

        if api_call["this"]["mode"] == 1:
            self.droidmon["crypto_data"].append(api_call["args"][0])
        else:
            self.droidmon["crypto_data"].append(api_call["result"])

    def java_lang_reflect_Method_invoke(self,api_call):
        reflection = ""
        if "hooked_class" in api_call:
            reflection = api_call["hooked_class"]+"->"+api_call["hooked_method"]
        else:
            reflection = api_call["hooked_method"]
        self.droidmon["reflection_calls"].add(reflection)

    def dalvik_system_BaseDexClassLoader_findResource(self,api_call):
        self.lib_pairs(api_call,"findResource")

    def android_app_Activity_startActivity(self,api_call):
        self.droidmon["started_activities"].append(api_call["args"][0])

    def java_lang_Runtime_exec(self,api_call):
        command = api_call["args"][0]
        if type(command) is list:
            self.droidmon["commands"].add(' '.join(command))
        else:
            self.droidmon["commands"].add(command)

    def java_lang_ProcessBuilder_start(self,api_call):
        command = api_call["this"]["command"]
        self.droidmon["commands"].add(' '.join(command))

    def libcore_io_IoBridge_open(self,api_call):
        self.droidmon["file_accessed"].add(api_call["args"][0])

    def android_app_ActivityThread_handleReceiver(self,api_call):
        self.droidmon["handleReceiver"].append(api_call["args"][0])

    def android_app_ContextImpl_registerReceiver(self,api_call):
        for arg in api_call["args"]:
            if "mActions" in arg:
                for action in arg["mActions"]:
                    self.droidmon["registered_receivers"].add(action)

    def android_telephony_TelephonyManager_getDeviceId(self,api_call):
        self.droidmon["fingerprint"].add("getDeviceId")

    def android_telephony_TelephonyManager_getNetworkOperatorName(self,api_call):
        self.droidmon["fingerprint"].add("getNetworkOperatorName")

    def android_telephony_TelephonyManager_getSubscriberId(self,api_call):
        self.droidmon["fingerprint"].add("getSubscriberId")

    def android_telephony_TelephonyManager_getLine1Number(self,api_call):
        self.droidmon["fingerprint"].add("getLine1Number")

    def android_telephony_TelephonyManager_getNetworkOperator(self,api_call):
        self.droidmon["fingerprint"].add("getNetworkOperator")

    def android_telephony_TelephonyManager_getSimOperatorName(self,api_call):
        self.droidmon["fingerprint"].add("getSimOperatorName")

    def android_telephony_TelephonyManager_getSimCountryIso(self,api_call):
        self.droidmon["fingerprint"].add("getSimCountryIso")

    def android_telephony_TelephonyManager_getSimSerialNumber(self,api_call):
        self.droidmon["fingerprint"].add("getSimSerialNumber")

    def android_telephony_TelephonyManager_getNetworkCountryIso(self,api_call):
        self.droidmon["fingerprint"].add("getNetworkCountryIso")

    def android_telephony_TelephonyManager_getDeviceSoftwareVersion(self,api_call):
        self.droidmon["fingerprint"].add("getDeviceSoftwareVersion")

    def android_net_wifi_WifiInfo_getMacAddress(self,api_call):
        self.droidmon["fingerprint"].add("getMacAddress")

    def android_app_SharedPreferencesImpl_EditorImpl_putInt(self,api_call):
        self.droidmon["SharedPreferences"].append(self.get_pair(api_call))

    def android_app_SharedPreferencesImpl_EditorImpl_putString(self,api_call):
        self.droidmon["SharedPreferences"].append(self.get_pair(api_call))

    def android_app_SharedPreferencesImpl_EditorImpl_putFloat(self,api_call):
        self.droidmon["SharedPreferences"].append(self.get_pair(api_call))

    def android_app_SharedPreferencesImpl_EditorImpl_putBoolean(self,api_call):
        self.droidmon["SharedPreferences"].append(self.get_pair(api_call))

    def android_app_SharedPreferencesImpl_EditorImpl_putLong(self,api_call):
        self.droidmon["SharedPreferences"].append(self.get_pair(api_call))

    def android_content_ContentResolver_query(self,api_call):
        self.droidmon["ContentResolver_queries"].add(api_call["args"][0]["uriString"])

    def android_telephony_TelephonyManager_getSubscriberId(self,api_call):
        self.droidmon["fingerprint"].add("getSubscriberId")

    def android_content_ContentValues_put(self,api_call):
        self.droidmon["ContentValues"].append(self.get_pair(api_call))

    def android_telephony_TelephonyManager_getNetworkCountryIso(self,api_call):
        self.droidmon["fingerprint"].add("getNetworkCountryIso")

    def javax_crypto_Mac_doFinal(self,api_call):
        self.droidmon["mac_data"].append(api_call["args"][0])

    def android_util_Base64_encodeToString(self,api_call):
        self.droidmon["encoded_base64"].append(api_call["args"][0])

    def android_util_Base64_encode(self,api_call):
        self.droidmon["encoded_base64"].append(api_call["result"][0])

    def android_app_ApplicationPackageManager_setComponentEnabledSetting(self,api_call):
        new_pair={}
        component= api_call["args"][0]
        new_pair["component_name"]= component["mPackage"]+"/"+component["mClass"]
        new_state=api_call["args"][1]

        if (new_state in "2"):
            new_pair["component_new_state"] = "COMPONENT_ENABLED_STATE_DISABLED"
        elif (new_state in "1"):
            new_pair["component_new_state"] = "COMPONENT_ENABLED_STATE_ENABLED"
        elif (new_state in "0"):
            new_pair["component_new_state"] = "COMPONENT_ENABLED_STATE_DEFAULT"
        self.droidmon["ComponentEnabledSetting"].append(new_pair)

    def android_location_Location_getLatitude(self,api_call):
        self.droidmon["data_leak"].add("location")

    def android_location_Location_getLongitude(self,api_call):
        self.droidmon["data_leak"].add("location")

    def android_app_ApplicationPackageManager_getInstalledPackages(self,api_call):
        self.droidmon["data_leak"].add("getInstalledPackages")

    def dalvik_system_BaseDexClassLoader_findLibrary(self,api_call):
        self.lib_pairs(api_call,"findLibrary")

    def android_telephony_SmsManager_sendTextMessage(self,api_call):
        new_pair={}
        new_pair["dest_number"]=api_call["args"][0]
        new_pair["content"]=' '.join(api_call["args"][1])
        self.droidmon["sms"].append(new_pair)

    def android_util_Base64_decode(self,api_call):
        self.droidmon["decoded_base64"].append(api_call["result"])

    def android_telephony_TelephonyManager_listen(self,api_call):
        event =  api_call["args"][1];
        listen_enent=""
        if event==16:
            listen_enent="LISTEN_CELL_LOCATION"
        elif event==256:
            listen_enent="LISTEN_SIGNAL_STRENGTHS"
        elif event==32:
            listen_enent="LISTEN_CALL_STATE"
        elif event==64:
            listen_enent="LISTEN_DATA_CONNECTION_STATE"
        elif event==1:
            listen_enent="LISTEN_SERVICE_STATE"
        if "" not in listen_enent:
            self.droidmon["TelephonyManager_listen"].add(listen_enent)

    def android_content_ContentResolver_registerContentObserver(self,api_call):
        self.droidmon["registerContentObserver"].add(api_call["args"][0]["uriString"])

    def android_content_ContentResolver_insert(self,api_call):
        self.droidmon["ContentResolver_queries"].add(api_call["args"][0]["uriString"])

    def android_accounts_AccountManager_getAccountsByType(self,api_call):
        self.droidmon["accounts"].add(api_call["args"][0])
        self.droidmon["data_leak"].add("getAccounts")

    def dalvik_system_BaseDexClassLoader_findResources(self,api_call):
        self.lib_pairs(api_call,"findResource")

    def android_accounts_AccountManager_getAccounts(self,api_call):
       self.droidmon["data_leak"].add("getAccounts")

    def android_telephony_SmsManager_sendMultipartTextMessage(self,api_call):
        new_pair={}
        new_pair["dest_number"]=api_call["args"][0]
        new_pair["content"]=api_call["args"][2]
        self.droidmon["sms"].append(new_pair)

    def android_content_ContentResolver_delete(self,api_call):
        self.droidmon["ContentResolver_queries"].add(api_call["args"][0]["uriString"])

    def android_media_AudioRecord_startRecording(self,api_call):
        self.droidmon["events"].add("mediaRecorder")

    def android_media_MediaRecorder_start(self,api_call):
        self.droidmon["events"].add("mediaRecorder")

    def android_content_BroadcastReceiver_abortBroadcast(self,api_call):
        self.droidmon["events"].add("abortBroadcast")

    def dalvik_system_DexFile_loadDex(self,api_call):
        self.droidmon["loadDex"].add(api_call["args"][0])

    def dalvik_system_DexClass_dalvik_system_DexClassLoader(self,api_call):
       self.droidmon["DexClassLoader"].append(api_call["args"])

    def dalvik_system_DexFile_dalvik_system_DexFile(self,api_call):
       self.droidmon["DexFile"].append(api_call["args"])

    def dalvik_system_PathClassLoader_dalvik_system_PathClassLoader(self,api_call):
        self.droidmon["PathClassLoader"].append(api_call["args"])

    def android_app_ActivityManager_killBackgroundProcesses(self,api_call):
        self.droidmon["killed_process"].append(api_call["args"][0])

    def android_os_Process_killProcess(self,api_call):
        self.droidmon["killed_process"].append(api_call["args"][0])
    
    def android_net_ConnectivityManager_setMobileDataEnabled(self,api_call):
        self.droidmon["setMobileDataEnabled"].append(api_call["args"][0])

    def org_apache_http_impl_client_AbstractHttpClient_execute(self,api_call):
        json = {}
        if type(api_call["args"][0]) is dict:
            json["request"]=api_call["args"][1]
        else:
            json["request"]=api_call["args"][0]
        json["response"]=api_call["result"]
        self.droidmon["httpConnections"].append(json)

    def java_net_URL_openConnection(self, api_call):
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

    def dalvik_system_DexFile_loadClass(self,api_call):
        self.droidmon["loadClass"].add(api_call["args"][0])

    def java_io_FileOutputStream_write(self,api_call):
        #self.droidmon["command_objects"].append(api_call)
        commands = api_call["buffer"].split('\n')
        for command in commands:
            self.droidmon["commands"].add(command)

    def java_io_FileInputStream_read(self,api_call):
        pass
        #self.droidmon["command_objects"].append(api_call)
        self.droidmon["commands_output"].add("read: "+api_call["buffer"])

    def get_pair(self,api_call):
        new_pair={}
        new_pair["key"]=api_call["args"][0]
        if(api_call["args"].__len__()>1):
            new_pair["value"]=api_call["args"][1]
        return new_pair

    def lib_pairs(self,api_call,key):
        libname=api_call["args"][0]
        exists=False
        for current_key in self.droidmon[key]:
            if libname in current_key["libname"]:
                exists=True
                break
        if not exists :
            new_pair={}
            new_pair["libname"]=api_call["args"][0]
            if "result" in api_call:
                new_pair["result"]=api_call["result"]
            else:
                new_pair["result"]=""
            self.droidmon[key].append(new_pair)

    def keyCleaner(self,d):
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
            return self.droidmon

        results = {}
        log_path = self.logs_path + "/droidmon.log"
        if not os.path.exists(log_path):
            return results

        try:
            with open(log_path) as log_file:
                for line in log_file:
                    try:
                        api_call = json.loads(line)
                        self.droidmon["raw"].append(self.keyCleaner(api_call))
                        call = api_call["class"]+"_"+api_call["method"]
                        if call in self.log_hook_method_map:
                            func = self.log_hook_method_map[call]
                            func(api_call)
                        else:
                            self.droidmon["error"].append(line)
                    except Exception as e:
                        log.error(CuckooProcessingError("error parsing json line: %s" % line + " error" + e.message))
        except Exception as e:
            raise CuckooProcessingError("Error opening file %s" % e)

        for key in self.droidmon.keys():
            if len(self.droidmon[key]) > 0:
                if type(self.droidmon[key]) is list:
                    results[key] = self.droidmon[key]
                else:
                    results[key] = list(self.droidmon[key])

        return results
