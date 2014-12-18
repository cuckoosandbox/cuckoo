# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import os
import logging
from zipfile import BadZipfile

from analyzer.android_on_linux.lib.api.androguard import apk
from analyzer.android_on_linux.lib.api.androguard import analysis
from analyzer.android_on_linux.lib.api.androguard import dvm
from lib.cuckoo.common.objects import File
from analyzer.android_on_linux.lib.core.packages import choose_package
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError



log = logging.getLogger(__name__)


class ApkInfo(Processing):
    """Static android information about analysis session."""

    def check_size(self,file_list):
        for file in file_list:
            if "classes.dex" in file["name"]:
                if("decompilation_threshold" in self.options):
                    if file["size"] < self.options.decompilation_threshold:
                        return True
                    else:
                        return False
                else:
                    return True
        return False

    def run(self):
        """Run androguard to extract static android information
                @return: list of static features
        """
        self.key = "apkinfo"
        apkinfo = {}

        if ("file" not in self.task["category"]):
            return

        if("apk" in choose_package(File(self.task["target"]).get_type(),File(self.task["target"]).get_name())):
            if not os.path.exists(self.file_path):
                raise CuckooProcessingError("Sample file doesn't exist: \"%s\"" % self.file_path)

            try :
                a = apk.APK(self.file_path )
                if a.is_valid_APK():

                    manifest ={}
                    apkinfo["files"]=a.get_files_with_md5()
                    manifest["package"]=a.get_package()
                    manifest["permissions"]=a.get_details_permissions_new()
                    manifest["main_activity"]=a.get_main_activity()
                    manifest["activities"]=a.get_activities()
                    manifest["services"]= a.get_services()
                    manifest["receivers"]=a.get_receivers()
                    manifest["receivers_actions"]=a.get__extended_receivers()
                    manifest["providers"]= a.get_providers()
                    manifest["libraries"] = a.get_libraries()
                    apkinfo["manifest"]=manifest
                    #apkinfo["certificate"] = a.get_certificate()
                    static_calls ={}
                    if self.check_size(apkinfo["files"]):
                        vm = dvm.DalvikVMFormat( a.get_dex())
                        vmx = analysis.uVMAnalysis(vm)

                        static_calls["all_methods"] =self.get_methods(vmx)
                        static_calls["is_native_code"] = analysis.is_native_code(vmx)
                        static_calls["is_dynamic_code"] = analysis.is_dyn_code(vmx)
                        static_calls["is_reflection_code"]= analysis.is_reflection_code(vmx)

                        static_calls["dynamic_method_calls"]= analysis.get_show_DynCode(vmx)
                        static_calls["reflection_method_calls"]= analysis.get_show_ReflectionCode(vmx)
                        static_calls["permissions_method_calls"]= analysis.get_show_Permissions(vmx)
                        static_calls["crypto_method_calls"]= analysis.get_show_CryptoCode(vmx)
                        static_calls["native_method_calls"]= analysis.get_show_NativeMethods(vmx)
                    else:
                        log.warning("Dex Size Bigger Then: "+str(self.options.decompilation_threshold))
                    apkinfo["static_method_calls"]=static_calls
            except (IOError, OSError,BadZipfile) as e:
                raise CuckooProcessingError("Error opening file %s" % e)

        return apkinfo

    def get_methods(self,vmx):
        methods=[]
        for i in vmx.get_methods() :
            method= {}
            i.create_tags()
            if not i.tags.empty() :
                proto =i.method.proto.replace('(','').replace(';','')
                protos = proto.split(')')
                params = protos[0].split(' ')
                method["class"]= i.method.get_class_name().replace(';','')
                method["name"]=i.method.name
                if(params.__len__()>0 and params[0]!=""):
                    method["params"] = params
                method["return"] = protos[1]
                methods.append(method)
        return methods