# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.http import JsonResponse

from cuckoo.core.database import Database
from cuckoo.web.utils import json_error_response, api_get

db = Database()

class MachinesApi:
    @api_get
    def list(request):
        """
        Returns a list of all machines currently registered in Cuckoo
        :return:
        """
        data = {}

        machines = db.list_machines()

        data["machines"] = []
        for row in machines:
            data["machines"].append(row.to_dict())

        return JsonResponse({"status": True, "data": data})

    @api_get
    def view(request, name=None):
        """
        Returns information about a machine
        :param name: machine name
        :return: Machine information as a dictionary
        """
        machine = db.view_machine(name=name)
        if machine:
            return JsonResponse({"status": True, "data": machine.to_dict()})
        else:
            return json_error_response("Machine not found")
