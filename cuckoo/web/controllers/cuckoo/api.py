# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import multiprocessing
import os
import socket

from django.http import JsonResponse

from cuckoo.common.files import Files
from cuckoo.core.database import Database
from cuckoo.core.rooter import rooter
from cuckoo.misc import cwd, version
from cuckoo.web.utils import json_fatal_response, api_get

db = Database()

class CuckooApi:
    @api_get
    def status(request):
        """
        Returns a variety of information about both
        Cuckoo and the operating system.
        :return: Dictionary
        """
        # In order to keep track of the diskspace statistics of the temporary
        # directory we create a temporary file so we can statvfs() on that.
        temp_file = Files.temp_put("")

        paths = dict(
            binaries=cwd("storage", "binaries"),
            analyses=cwd("storage", "analyses"),
            temporary=os.path.dirname(temp_file),
        )

        diskspace = {}
        for key, path in paths.items():
            if hasattr(os, "statvfs") and os.path.isdir(path):
                stats = os.statvfs(path)
                diskspace[key] = dict(
                    free=stats.f_bavail * stats.f_frsize,
                    total=stats.f_blocks * stats.f_frsize,
                    used=(stats.f_blocks - stats.f_bavail) * stats.f_frsize,
                )

        # Now we remove the temporary file and its parent directory.
        os.unlink(temp_file)

        # Get the CPU load.
        if hasattr(os, "getloadavg"):
            cpuload = os.getloadavg()
        else:
            cpuload = []

        try:
            cpucount = multiprocessing.cpu_count()
        except NotImplementedError:
            cpucount = 1

        if os.path.isfile("/proc/meminfo"):
            values = {}
            for line in open("/proc/meminfo"):
                key, value = line.split(":", 1)
                values[key.strip()] = value.replace("kB", "").strip()

            if "MemAvailable" in values and "MemTotal" in values:
                memavail = int(values["MemAvailable"])
                memtotal = int(values["MemTotal"])
                memory = 100 - 100.0 * memavail / memtotal
            else:
                memory = memavail = memtotal = None
        else:
            memory = memavail = memtotal = None

        data = dict(
            version=version,
            hostname=socket.gethostname(),
            machines=dict(
                total=len(db.list_machines()),
                available=db.count_machines_available()
            ),
            tasks=dict(
                total=db.count_tasks(),
                pending=db.count_tasks("pending"),
                running=db.count_tasks("running"),
                completed=db.count_tasks("completed"),
                reported=db.count_tasks("reported")
            ),
            diskspace=diskspace,
            cpucount=cpucount,
            cpuload=cpuload,
            memory=memory,
            memavail=memavail,
            memtotal=memtotal,
        )

        return JsonResponse({"status": True, "data": data})

    @api_get
    def vpn_status(request):
        status = rooter("vpn_status")
        if status is None:
            return json_fatal_response("Rooter not available")

        return JsonResponse({"status": True, "vpns": status})
