# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com), Updated 2016 for cuckoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class StealthChildProc(Signature):
    name = "stealth_childproc"
    description = "Forces a created process to be the child of an unrelated process"
    severity = 3
    categories = ["stealth"]
    authors = ["Optiv"]
    minimum = "2.0"

    filter_apinames = [
        "NtCreateProcess",
        "NtCreateProcessEx",
        "RtlCreateUserProcess",
        "CreateProcessInternalW",
    ]

    current_process = [
        "0xffffffff",
        "0xffffffffffffffff",
    ]

    def on_call(self, call, process):
        process_handle = call["arguments"].get("parent_process_handle")
        if process_handle and process_handle not in self.current_process:
            self.mark_call()

    def on_complete(self):
        return self.has_marks()
