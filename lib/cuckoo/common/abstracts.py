import os
import ConfigParser

from lib.cuckoo.common.constants import CUCKOO_GUEST_SSL, CUCKOO_GUEST_PORT

class Dictionary(dict):
    def __getattr__(self, key):
        return self.get(key, None)

    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

class MachineManager(object):
    def __init__(self):
        self.module_name = ""
        self.config_path = ""
        self.config = ConfigParser.ConfigParser()
        self.options = {}
        self.machines = []

    def initialize(self, module_name):
        self.module_name = module_name
        self.config_path = "conf/%s.conf" % module_name
        self.config.read(self.config_path)

        machines_list = self.config.get(self.module_name, "machines").strip().split(",")
        for machine_id in machines_list:
            machine = Dictionary()
            machine.id = machine_id
            machine.label = self.config.get(machine_id, "label")
            machine.platform = self.config.get(machine_id, "platform")
            machine.ip = self.config.get(machine_id, "ip")

            try:
                machine.ssl = self.config.get(machine_id, "agent_ssl_enabled")
            except:
                machine.ssl = CUCKOO_GUEST_SSL

            try:
                machine.agent_url = self.config.get(machine_id, "agent_url")
            except:
                machine.agent_url = "%s://%s:%s" % machine.ssl ? "https" : "http", machine.ip, CUCKOO_GUEST_PORT

            machine.locked = False
            self.machines.append(machine)

    def acquire(self, label=None, platform=None):
        if label:
            for machine in self.machines:
                if machine.label == label and not machine.locked:
                    machine.locked = True
                    return machine
        elif platform:
            for machine in self.machines:
                if machine.platform == platform and not machine.locked:
                    machine.locked = True
                    return machine
        else:
            for machine in self.machines:
                if not machine.locked:
                    machine.locked = True
                    return machine

        return None

    def release(self, label=None):
        if label:
            for machine in self.machines:
                if machine.label == label:
                    machine.locked = False

    def start(self, label=None):
        raise NotImplementedError

    def stop(self, label=None):
        raise NotImplementedError

class Processing(object):
    def __init__(self):
        self.analysis_path = ""
        self.logs_path = ""

    def set_path(self, analysis_path):
        self.analysis_path = analysis_path
        self.log_path = os.path.join(analysis_path, "analysis.log")
        self.conf_path = os.path.join(analysis_path, "analysis.conf")
        self.file_path = os.path.join(analysis_path, "binary")
        self.dropped_path = os.path.join(analysis_path, "files")
        self.logs_path = os.path.join(analysis_path, "logs")
        self.pcap_path = os.path.join(analysis_path, "dump.pcap")

    def run(self):
        raise NotImplementedError

class Signature(object):
    name = ""
    description = ""
    severity = 1
    references = []
    alert = False
    enabled = True

    def __init__(self):
        self.data = []

    def run(self, results=None):
        raise NotImplementedError
        
class Report(object):
    def __init__(self):
        self.analysis_path = ""
        self.reports_path = ""
        self.options = None

    def set_path(self, analysis_path):
        self.analysis_path = analysis_path
        self.reports_path = os.path.join(self.analysis_path, "reports")

        if not os.path.exists(self.reports_path):
            os.mkdir(self.reports_path)

    def set_options(self, options):
        self.options = options

    def run(self):
        raise NotImplementedError
