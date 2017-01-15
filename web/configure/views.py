# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys,os
import shutil
from collections import OrderedDict
from django.conf import settings
from django.shortcuts import render
from django.views.decorators.http import require_safe
from django.views.decorators.csrf import csrf_exempt
from django.template.defaultfilters import register
from django.http import HttpResponseRedirect, HttpResponse
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.config import Config
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.startup import cuckoo_clean


sys.path.insert(0, settings.CUCKOO_PATH)

from ConfigParser import SafeConfigParser

@register.filter
def select_config(text):
    select = [('yes', 'no'), ('on', 'off'), ('enable', 'disable'), ('true', 'false')]
    for s in select:
        if text in s:
            return s
    return None

@csrf_exempt
def add(request):
    machine = request.POST.get("machine")
    platform = request.POST.get("platform")
    ethernet = request.POST.get("ethernet")
    ipaddress = request.POST.get("ipaddress")
    tags = request.POST.get("tags")
    snapshot = request.POST.get("snapshot")
    options = request.POST.get("options")
    current_machinery = request.POST.get("current_machinery")
    try:
        db = Database()
        conf = Config()
        resultserver_ip = conf.resultserver.ip
        resultserver_port = conf.resultserver.port
        if db.view_machine(machine):
            return HttpResponseRedirect("/configure")
        db.add_machine(machine, machine, ipaddress, platform, 
                options, tags, ethernet, snapshot, 
                resultserver_ip, int(resultserver_port))
        db.unlock_machine(machine)
        configure_file = os.path.join(CUCKOO_ROOT, 'conf', '%s.conf' % current_machinery)
        parser = SafeConfigParser()
        parser.read(configure_file)
        machines = set(parser.get(current_machinery, 'machines').split())
        machines.add(machine)
        parser.set(current_machinery, 'machines', ",".join(machines))
        parser.add_section(machine)
        parser.set(machine, 'label', machine)
        parser.set(machine, 'platform', platform)
        parser.set(machine, 'ip', ipaddress)
        with open(configure_file, "w+") as configfile:
            parser.write(configfile)
    except : pass
    return HttpResponseRedirect("/configure")

@csrf_exempt
def delete(request):
    machine = request.POST.get("machine")
    db = Database()
    db.unlock_machine(machine)
    current_machinery = request.POST.get("current_machinery")
    try:
        configure_file = os.path.join(CUCKOO_ROOT, 'conf', '%s.conf' % current_machinery)
        parser = SafeConfigParser()
        parser.read(configure_file)
        machines = parser.get(current_machinery, 'machines').split()
        machines.remove(machine)
        parser.set(current_machinery, 'machines', ",".join(machines))
        parser.remove_section(machine)
        with open(configure_file, "w+") as configfile:
            parser.write(configfile)
    except : pass
    return HttpResponseRedirect("/configure")

@csrf_exempt
def index(request):
    machinery = ['physical', 'virtualbox', 'vmware', 'vsphere', 'esx', 'xenserver', 'kvm', 'qemu', 'avd']
    config_list = ['cuckoo', 'reporting', 'processing', 'memory', 'auxiliary', 'vpn', 'physical', 'virtualbox', 'vmware', 'vsphere', 'esx', 'xenserver', 'kvm', 'qemu', 'avd']
    config_dir = os.path.join(CUCKOO_ROOT, 'conf')
    configure = OrderedDict()
    configure_files = []
    list_machines = []
    # cat /etc/sudoers.d/cuckoo 
    # cuckoo ALL=NOPASSWD: /sbin/shutdown
    # cuckoo ALL=NOPASSWD: /sbin/reboot
    # cuckoo ALL=NOPASSWD: /sbin/initctl
    action = request.POST.get("action")
    if action == 'clean':
        cuckoo_clean()
    if action == 'reboot':
        os.system('sudo reboot')
    if action == 'shutdown':
        os.system('sudo shutdown -h now')
    if action == 'restart':
        os.system('sudo initctl restart cuckoo-router')
        os.system('sudo initctl restart cuckoo')
        os.system('sudo initctl restart cuckoo-web')
    if action == 'log':
        path = os.path.join(CUCKOO_ROOT, 'log', 'cuckoo.log')
        logfile = open(path)
        response = HttpResponse(logfile.read(), content_type='application/octet-stream; charset=UTF-8')
        logfile.close()
        response['Content-Disposition'] = 'attachment; filename="cuckoo.log"'
        response['Content-Length'] = os.path.getsize(path)
        return response

    if action == 'load':
        configName = request.POST.get("configName")
        if configName is not None:
            snapshot_dir = os.path.join(CUCKOO_ROOT, 'snapshot', configName)
            for c in config_list:
                path = os.path.join(snapshot_dir, '%s.conf' % c)
                if os.path.exists(path):
                    shutil.copy(path, config_dir)
            return HttpResponseRedirect("/configure")

    # Read Config Files
    for c in config_list:
        configure_files.append({'name':c ,'file':os.path.join(config_dir, '%s.conf' % c)})
    #configure_files.append({'name':'moloch', 'file':'/data/moloch/etc/config.ini'})
    # TODO escape string (%)

    for cfg  in configure_files:
        c = cfg['name']
        configure_file = cfg['file']
        if not os.path.exists(configure_file):continue
        parser = SafeConfigParser()
        parser.read(configure_file)
        sections = parser.sections()
        configure[c] = {}
        for section in sections:
            items = parser.items(section)
            rewrite_items = []
            for item in items:
                r = request.POST.get("%s.%s.%s" % (c, section, item[0]))
                if r is not None and r != item[1]:
                    # print "%s.%s.%s -> %s" % (c, section, item[0], r)
                    rewrite_items.append((item[0], r))
                    parser.set(section, item[0], r)
                    with open(configure_file, "w+") as configfile:
                        parser.write(configfile)
                else:
                    rewrite_items.append(item)
                if c == 'cuckoo' and item[0] == 'machinery':
                    current_machinery = r if r is not None else item[1]
                    machinery.remove(current_machinery)
            configure[c][section] = rewrite_items

    if action == 'save':
        configName = request.POST.get("configName")
        if configName:
            snapshot_dir = os.path.join(CUCKOO_ROOT, 'snapshot', configName)
            try:
                os.makedirs(snapshot_dir)
            except : pass
            for c in config_list:
                shutil.copy(os.path.join(config_dir, '%s.conf' % c), snapshot_dir)
    configNames = os.listdir(os.path.join(CUCKOO_ROOT, 'snapshot'))
    db = Database()
    for machine in db.list_machines():
         list_machines.append(machine.to_dict()['name'])
    return render(request, "configure/index.html", {
        "configNames": configNames,
        "configure": configure,
        "machinery": machinery,
        "current_machinery": current_machinery,
        "list_machines":list_machines,
    })
