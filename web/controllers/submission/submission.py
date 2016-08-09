# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from sflock.abstracts import File

class SubmissionController:
    def __init__(self):
        pass

    def presubmit(self, filename, buffer, password=None):
        if filename.endswith((".zip", ".gz", ".tar", ".tar.gz", ".bz2")):
            f = File(contents=buffer)
            signature = f.get_signature()
            data = {"file": f, "unpacked": []}

            container = signature["unpacker"](f=f)

            for entry in container.unpack(mode=signature["mode"]):
                data["unpacked"].append(entry)

            return data
        else:
            return File(contents=buffer)

    def submit(self):
        pass