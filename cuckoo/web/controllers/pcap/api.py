# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from cuckoo.misc import cwd
from cuckoo.web.utils import json_error_response, file_response, api_get

class PcapApi:
    @api_get
    def get(request, task_id):
        file_path = cwd("dump.pcap", analysis=task_id)
        if not os.path.exists(file_path):
            return json_error_response("File not found")

        return file_response(
            data=open(file_path, "rb"),
            filename="analysis_pcap_dump_%s.pcap" % str(task_id),
            content_type="application/octet-stream; charset=UTF-8"
        )
