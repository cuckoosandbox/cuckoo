# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com), Updated 2016 for Cuckoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature
import struct

class Bootkit(Signature):
    name = "bootkit"
    description = "Likely installs a bootkit via raw harddisk modifications"
    severity = 3
    categories = ["rootkit"]
    authors = ["Optiv"]
    minimum = "2.0"
    evented = True

    BasicFileInformation = 4

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = 0
        self.handles = dict()
        self.saw_stealth = False
        self.bootkit = False

    filter_apinames = set(["NtCreateFile", "NtDuplicateObject", "NtOpenFile", "NtClose", "NtSetInformationFile", "NtWriteFile", "DeviceIoControl", "NtDeviceIoControlFile"])

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.handles = dict()
            self.lastprocess = process

        if call["api"] == "NtDuplicateObject" and call["status"]:
            tgtarg = call["arguments"]["target_handle"]
            if tgtarg:
                srchandle = int(call["arguments"]["source_handle"], 16)
                tgthandle = tgtarg
                if srchandle in self.handles:
                    self.handles[tgthandle] = self.handles[srchandle]
        elif call["api"] == "NtClose":
            handle = int(call["arguments"]["handle"], 16)
            self.handles.pop(handle, None)
        elif (call["api"] == "NtCreateFile" or call["api"] == "NtOpenFile") and call["status"]:
            filename = call["arguments"]["filepath"]
            handle = int(call["arguments"]["file_handle"], 16)
            access = int(call["arguments"]["desired_access"], 16)
            # FILE_WRITE_ACCESS or GENERIC_WRITE
            if filename and (filename.lower() == "\\??\\physicaldrive0" or filename.lower().startswith("\\device\\harddisk")) and access & 0x40000002:
                if handle not in self.handles:
                    self.handles[handle] = filename
                    self.mark_call()
        elif (call["api"] == "DeviceIoControl" or call["api"] == "NtDeviceIoControlFile") and call["status"]:
            ioctl = call["flags"]["control_code"]
            if call["api"] == "DeviceIoControl":
                handle = int(call["arguments"]["device_handle"], 16)
            else:
                handle = int(call["arguments"]["file_handle"], 16) 
            # IOCTL_SCSI_PASS_THROUGH_DIRECT
            if handle in self.handles and ioctl == "IOCTL_SCSI_PASS_THROUGH_DIRECT":
                self.mark_call()
                self.bootkit = True
        elif call["api"] == "NtWriteFile":
            handle = int(call["arguments"]["file_handle"], 16)
            if handle in self.handles:
                self.mark_call()
                self.bootkit = True

    def on_complete(self):
        if self.bootkit:
            return self.has_marks()        
