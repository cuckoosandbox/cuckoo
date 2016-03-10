# Copyright (C) Dmitry Rodionov.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DarwinCodeInjection(Signature):
    """ This signature will be triggered when a target process performs
    code injection with task_for_pid() and thread_create*() Mach APIs.
    See also: windows/injection_thread.py. """

    name = "darwin_code_injection"
    description = "TBD"
    severity = 3
    categories = ["injection"]
    authors = ["rodionovd"]
    minimum = "2.0"

    filter_apinames = [
        "task_for_pid",
        "vm_write", "mach_vm_write",
        "vm_allocate", "mach_vm_allocate",
        "thread_create_running", "thread_create", "thread_set_state", "thread_resume"
    ]

    def init(self):
        self.apis = {
            # We'll track API usage for each target process separately
        }

    def on_process(self, process):
        self.apis[process["pid"]] = set()

    def on_call(self, call, process):
        self.apis[process["pid"]].add(call["api"])
        self.mark_call()

    def on_complete(self):
        for _, apis in self.apis.items():
            # We don't care about processes that didn't call task_for_pid()
            if "task_for_pid" not in apis:
                continue
            if len(apis) >= len(self.filter_apinames)-4:
                return True
