# Copyright (C) Dmitry Rodionov.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class TaskForPid(Signature):
    """ This signature will be triggered when a target process
    calls task_for_pid(). """

    name = "task_for_pid"
    description = "task_for_pid() usage"
    severity = 2
    categories = ["injection"]
    authors = ["rodionovd"]
    minimum = "2.0"

    filter_apinames = ["task_for_pid"]

    def on_call(self, call, process):
        self.mark_call()
        return True
