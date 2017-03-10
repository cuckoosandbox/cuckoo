# Copyright (C) 2015-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import hashlib
import logging
import os
import zipfile

from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import uVMAnalysis
from androguard.core.analysis import analysis

from cuckoo.common.objects import File
from cuckoo.common.abstracts import Processing
from cuckoo.common.exceptions import CuckooProcessingError

log = logging.getLogger(__name__)

class ApkInfo(Processing):
    """Static android information about analysis session."""

    def check_size(self, file_list):
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

    def _apk_files(self, apk):
        """Returns a list of files in the APK."""
        ret = []
        for fname, filetype in apk.get_files_types().items():
            buf = apk.zip.read(fname)
            ret.append({
                "name": fname,
                "md5": hashlib.md5(buf).hexdigest(),
                "size": len(buf),
                "type": filetype,
            })
        return ret

    def run(self):
        """Run androguard to extract static android information
                @return: list of static features
        """
        self.key = "apkinfo"
        apkinfo = {}

        if "file" not in self.task["category"]:
            return

        f = File(self.task["target"])
        if f.get_name().endswith((".zip", ".apk")) or "zip" in f.get_type():
            if not os.path.exists(self.file_path):
                raise CuckooProcessingError("Sample file doesn't exist: \"%s\"" % self.file_path)

            try:
                a = APK(self.file_path)
                if a.is_valid_APK():
                    manifest = {}
                    apkinfo["files"] = self._apk_files(a)
                    manifest["package"] = a.get_package()
                    # manifest["permissions"]=a.get_details_permissions_new()
                    manifest["main_activity"] = a.get_main_activity()
                    manifest["activities"] = a.get_activities()
                    manifest["services"] = a.get_services()
                    manifest["receivers"] = a.get_receivers()
                    # manifest["receivers_actions"]=a.get__extended_receivers()
                    manifest["providers"] = a.get_providers()
                    manifest["libraries"] = a.get_libraries()
                    apkinfo["manifest"] = manifest
                    # apkinfo["certificate"] = a.get_certificate()
                    static_calls = {}
                    if self.check_size(apkinfo["files"]):
                        vm = DalvikVMFormat(a.get_dex())
                        vmx = uVMAnalysis(vm)

                        static_calls["all_methods"] = self.get_methods(vmx)
                        static_calls["is_native_code"] = analysis.is_native_code(vmx)
                        static_calls["is_dynamic_code"] = analysis.is_dyn_code(vmx)
                        static_calls["is_reflection_code"] = analysis.is_reflection_code(vmx)

                        # static_calls["dynamic_method_calls"]= analysis.get_show_DynCode(vmx)
                        # static_calls["reflection_method_calls"]= analysis.get_show_ReflectionCode(vmx)
                        # static_calls["permissions_method_calls"]= analysis.get_show_Permissions(vmx)
                        # static_calls["crypto_method_calls"]= analysis.get_show_CryptoCode(vmx)
                        # static_calls["native_method_calls"]= analysis.get_show_NativeMethods(vmx)
                    else:
                        log.warning("Dex size bigger than: %s",
                                    self.options.decompilation_threshold)
                    apkinfo["static_method_calls"] = static_calls
            except (IOError, OSError, zipfile.BadZipfile) as e:
                raise CuckooProcessingError("Error opening file %s" % e)

        return apkinfo

    def get_methods(self, vmx):
        methods = []
        for i in vmx.get_methods():
            method = {}
            i.create_tags()
            if not i.tags.empty():
                proto = i.method.proto.replace("(", "").replace(";", "")
                protos = proto.split(")")
                params = protos[0].split(" ")
                method["class"] = i.method.get_class_name().replace(";", "")
                method["name"] = i.method.name
                if params and params[0]:
                    method["params"] = params
                method["return"] = protos[1]
                methods.append(method)
        return methods
