# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from cuckoo.misc import cwd

from bin.utils import json_error_response, json_fatal_response, file_response, api_get

class PcapApi:
    @api_get
    def get(request, task_id):
        file_path = os.path.join(cwd(), "storage", "analyses", "%d" % task_id, "dump.pcap")
        if os.path.exists(file_path):
            try:
                response = file_response(data=open(file_path, "rb"),
                                         filename="analysis_pcap_dump_%s.pcap" % str(task_id),
                                         content_type="application/octet-stream; charset=UTF-8")
                return response
            except:
                return json_fatal_response("An error occurred while reading PCAP")
        else:
            return json_error_response("File not found")
