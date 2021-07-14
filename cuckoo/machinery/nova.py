# Copyright (C) 2017 Robert Putt
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.


import logging
import requests
import json
import time
from cuckoo.common.abstracts import Machinery
from cuckoo.common.exceptions import CuckooMachineError


log = logging.getLogger(__name__)


class Nova(Machinery):

    LABEL = 'uuid'

    def _get_token(self):
        log.info("Attempting to fetch token from Keystone")
        rax_auth = self.options.nova.rackspace_auth
        keystone_url = self.options.nova.keystone_url
        username = self.options.nova.username
        password = self.options.nova.password
        default_image = self.options.nova.default_image_uuid

        if rax_auth:
            auth_body = {"auth":
                            {"RAX-KSKEY:apiKeyCredentials":
                                {"username":username,
                                 "apiKey":password
                                 }
                             }
                         }
        else:
            auth_body = {"auth": {
                            "identity": {
                                "methods": ["password"],
                                "password": {
                                    "user": {
                                        "id": username,
                                        "password": password
                                    }
                                }
                            },
                            "scope": "unscoped"
                            }
                         }

        auth_url = "%s/tokens" % keystone_url
        headers = {'content-type': 'application/json'}

        try:
            auth_resp = requests.post(auth_url,
                                      data=json.dumps(auth_body),
                                      headers=headers)

            if auth_resp.status_code == 200:
                token_data = json.loads(auth_resp.text)
                token = token_data['access']['token']['id']
                return token

            else:
                log.error("Non OK response from Keystone.")
                raise Exception()

        except:
            raise CuckooMachineError("Failed to fetch auth token from "
                                     "Keystone server.")

    def _issue_server_rebuild(self, server_uuid):
        image_uuid = self.options.nova.default_image_uuid
        nova_url = self.options.nova.nova_url

        token = self._get_token()
        action_body = {"rebuild" :{
                                   "imageRef" : image_uuid
                                   }
                       }
        url = "%s/servers/%s/action" % (nova_url, server_uuid)

        headers = {"content-type": "application/json",
                   "X-Auth-Token": token}

        try:
            rebuild_resp = requests.post(url,
                                         data=json.dumps(action_body),
                                         headers=headers)

            if rebuild_resp.status_code != 202:
                raise Exception()

        except:
            raise CuckooMachineError("Failed to instruct nova to "
                                     "rebuild host from image.")

    def _get_server_status(self, server_uuid):
        token = self._get_token()
        nova_url = self.options.nova.nova_url

        url = "%s/servers/%s" % (nova_url, server_uuid)
        headers = {"content-type": "application/json",
                   "X-Auth-Token": token}

        try:
            status_resp = requests.get(url, headers=headers)
            if status_resp.status_code == 200:
                server_data = json.loads(status_resp.text)
                return server_data['server']['status']

            else:
                raise CuckooMachineError("Received bad status code from Nova "
                                         "API when requesting server status.")
        except:
            log.warn("Failed to get server status from nova.")

    def start(self, machine_label, task):
        status = self._get_server_status(machine_label)
        log.info("Checking if server %s is ready" % machine_label)
        if status != "ACTIVE":
            log.info("Server does not appear to be active, "
                     "raising machine error")
            raise CuckooMachineError("Nova server %s does not appear to "
                                     "be in an active state" % machine_label)

    def stop(self, machine_label):
        log.info("Kicking off rebuild for host via Nova.")
        self._issue_server_rebuild(machine_label)
        complete = False

        while not complete:
            log.info("Checking if host has completed rebuild.")
            status = self._get_server_status(machine_label)

            if status == "REBUILD":
                log.info("Server %s is still rebuilding" % machine_label)
            else:
                log.info("Server %s is no longer in rebuild state"
                         % machine_label)
                complete = True

            time.sleep(30)

