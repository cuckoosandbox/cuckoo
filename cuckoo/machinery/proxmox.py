# Copyright (C) 2017 Menlo Security

import bs4
import logging
import requests
import socket
import subprocess
import wakeonlan.wol
import xmlrpclib


from cuckoo.common.config import config
from cuckoo.common.exceptions import CuckooCriticalError
from cuckoo.common.exceptions import CuckooMachineError
from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.common.exceptions import CuckooReportError
from cuckoo.common.exceptions import CuckooDependencyError
from cuckoo.common.files import Folders
from cuckoo.common.objects import Dictionary
from cuckoo.core.database import Database
from cuckoo.misc import cwd

from cuckoo.common.abstracts import Machinery
from proxmoxer import ProxmoxAPI

class Proxmox(Machinery):
    """Manage Proxmox sandboxes."""
        
    def __init__(self):
        self.options = None
        self.db = Database()
        self.vms = {}
        
        # Machine table is cleaned to be filled from configuration file
        # at each start.
        self.db.clean_machines()

    def _initialize(self, module_name):
        """Read configuration.
        @param module_name: module name.
        """
        machinery = self.options.get(module_name)
        
        
        for vmname in machinery["machines"]:
            options = self.options.get(vmname)

            # If configured, use specific network interface for this
            # machine, else use the default value.
            if options.get("interface"):
                interface = options["interface"]
            else:
                interface = machinery.get("interface")
           
            if options.get("resultserver_ip"):
                ip = options["resultserver_ip"]
            else:
                ip = config("cuckoo:resultserver:ip")

            if options.get("resultserver_port"):
                port = options["resultserver_port"]
            else:
                # The ResultServer port might have been dynamically changed,
                # get it from the ResultServer singleton. Also avoid import
                # recursion issues by importing ResultServer here.
                from cuckoo.core.resultserver import ResultServer
                port = ResultServer().port

            self.db.add_machine(
                name=vmname,
                label=options[self.LABEL],
                ip=options.ip,
                platform=options.platform,
                options=options.get("options", ""),
                tags=options.tags,
                interface=interface,
                snapshot=options.snapshot,
                vmid=options.vmid,
                resultserver_ip=ip,
                resultserver_port=port
            )
    
    
    def _initialize_check(self):
        """Ensures that credentials have been entered into the config file.
        @raise CuckooCriticalError: if no credentials were provided
        """
        # TODO This should be moved to a per-machine thing.
        if not self.options.proxmox.username or not self.options.proxmox.password:
            raise CuckooCriticalError(
                "Proxmox credentials are missing, please add it to "
                "the Proxmox machinery configuration file."
            )
        if not self.options.proxmox.hostname:
            raise CuckooCriticalError(
                "Proxmox hostname not set"
            )
            
    def login(self):
      proxmox = ProxmoxAPI(self.options.proxmox.hostname, user=self.options.proxmox.username,
                     password=self.options.proxmox.password, verify_ssl=False)
      for node in proxmox.nodes.get():
        if 'uptime' in node:
          for vm in proxmox.nodes(node['node']).qemu.get():
            vmid = str(vm['vmid'])
            self.vms[vmid] = {}
            self.vms[vmid]['node'] = node['node']
            self.vms[vmid]['name'] = vm['name']
            self.vms[vmid]['status'] = vm['status']
            print self.vms[vmid]
      return proxmox

    def start(self, label, task):
        try:
            proxmox = self.login()
            vmid = str(self.db.view_machine_by_label(label).vmid)
            snapshot = self.db.view_machine_by_label(label).snapshot
            print "label: %s, task: %s" % (label,task)
            proxmox.nodes(self.vms[vmid]['node']).qemu(vmid).snapshot(snapshot).rollback.post()
        except OSError as e:
            raise CuckooMachineError("oops! couldn't restore VM %s to snapshot %s - %s" % (vmid,snapshot, e) )

    def stop(self, label):
        try:
            proxmox = self.login()
            vmid = str(self.db.view_machine_by_label(label).vmid)
            print "VMID:-"
            print self.vms
            proxmox.nodes(self.vms[vmid]['node']).qemu(vmid).status.stop.post()
        except OSError as e:
            raise CuckooMachineError("oops! Couldn't stop VM. %s - %s" % (vmid, e) )

