# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ConfigParser
import os
import logging

from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.common.objects import Dictionary
from cuckoo.misc import cwd

log = logging.getLogger(__name__)

class Config:
    """Configuration file parser."""

    # Config Parameters and their types
    BOOLEAN,STRING,INT,PATH,IP = range(5)
    ParamTypes = {
        ## cuckoo.conf parameters
        'version_check':BOOLEAN,
        'delete_original':BOOLEAN,
        'delete_bin_copy':BOOLEAN,
        'machinery':STRING,
        'memory_dump':BOOLEAN,
        'terminate_processes':BOOLEAN,
        'reschedule':BOOLEAN,
        'process_results':BOOLEAN,
        'max_analysis_count':INT,
        'max_machines_count':INT,
        'max_vmstartup_count':INT,
        'freespace':INT,
        'tmppath':PATH,
        'rooter':PATH,
        'ip':IP,
        'port':INT,
        'force_port':BOOLEAN,
        'upload_max_size':INT,
        'analysis_size_limit':INT,
        'resolve_dns':BOOLEAN,
        'sort_pcap':BOOLEAN,
        'connection':STRING,
        'timeout':INT,
        'default':INT,
        'critical':INT,
        'vm_state':INT,
        ## virtualbox.conf parameters
        'mode': STRING,
        'path':PATH,
        'interface':STRING,
        'machines':STRING,
        'label':STRING,
        'platform':STRING,
        'snapshot':STRING,
        'resultserver_ip':IP,
        'resultserver_port':INT,
        'tags':STRING,
        'options':STRING,
        ## auxiliary.conf parameters
        'enabled':BOOLEAN,
        'tcpdump':PATH,
        'mitmdump':PATH,
        'port_base':INT,
        'script':PATH,
        'bpf':STRING,
        'certificate':PATH,
        'services':STRING,
        ## avd.conf parameters
        'emulator_path':PATH,
        'adb_path': PATH,
        'avd_path': PATH,
        'reference_machine':STRING,
        'emulator_port':INT,
        ## esx.conf parameters
        'dsn':STRING,
        'username':STRING,
        'password':STRING,
        ## kvm.conf parameters
        ## memory.conf parameters
        'guest_profile':STRING,
        'delete_memdump':STRING,
        'filter':BOOLEAN,
        'pid_generic':STRING,
        ## physical.conf parameters
        'user':STRING,
        'hostname':STRING,
        ## processing.conf parameters
        'android_id':STRING,
        'google_login':STRING,
        'google_password':STRING,
        'decompilation_threshold':INT,
        'url':STRING,
        'apikey':STRING,
        'maxioc':INT,
        'idapro':BOOLEAN,
        'extract_img':BOOLEAN,
        'dump_delete':BOOLEAN,
        'tesseract':BOOLEAN,
        'snort':PATH,
        'conf':PATH,
        'suricata':PATH,
        'eve_log':PATH,
        'files_log':PATH,
        'files_dir':PATH,
        'socket':PATH,
        'scan':BOOLEAN,
        'key':STRING,
        'force':BOOLEAN,
        ## qemu.conf parameters
        'image':PATH,
        'arch':STRING,
        'kernel_path':PATH,
        ## reporting.conf parameters
        'identifier':STRING,
        'moloch_capture':PATH,
        'instance':STRING,
        'host':IP,
        'hosts':STRING,
        'index_time_pattern':STRING,
        'index':STRING,
        'calls':BOOLEAN,
        'paginate':INT,
        'store_memdump':BOOLEAN,
        'db':STRING,
        'encoding':STRING,
        'indent':INT,
        ## routing.conf parameters
        'name':STRING,
        'description':STRING,
        'rt_table':STRING,
        'vpns':STRING,
        'dnsport':INT,
        'proxyport':INT,
        'server':IP,
        'drop':BOOLEAN,
        'auto_rt':BOOLEAN,
        'internet':STRING,
        'route':STRING,
        ## vmware.conf parameters
        'vmx_path':PATH,
        ## vsphere.conf parameters
        'pwd':STRING,
        'unverified_ssl':BOOLEAN,
        ## xenserver.conf parameters
        'uuid':STRING,
    }

    def __init__(self, file_name="cuckoo", cfg=None):
        """
        @param file_name: file name without extension.
        @param cfg: configuration file path.
        """
        env = {}
        for key, value in os.environ.items():
            if key.startswith("CUCKOO_"):
                env[key] = value

        config = ConfigParser.ConfigParser(env)

        if cfg:
            config.read(cfg)
        else:
            config.read(cwd("conf", "%s.conf" % file_name))

        for section in config.sections():
            setattr(self, section, Dictionary())
            for name, raw_value in config.items(section):
                if name in self.ParamTypes:
                    if self.ParamTypes[name] in [self.STRING , self.PATH , self.IP ]:
                        value = config.get(section,name)
                    elif self.ParamTypes[name] is self.INT:
                        try:
                            value = config.getint(section,name)
                        except ValueError:
                            value = config.get(section,name)
                    elif self.ParamTypes[name] is self.BOOLEAN:
                        try:
                            value = config.getboolean(section, name)
                        except ValueError:
                            value = config.get(section,name)
                else:
                    value = config.get(section, name)
                    log.error("Type of config parameter %s.%s NOT FOUND!!"%(section,name))
                setattr(getattr(self, section), name, value)

    def get(self, section):
        """Get option.
        @param section: section to fetch.
        @raise CuckooOperationalError: if section not found.
        @return: option value.
        """
        try:
            return getattr(self, section)
        except AttributeError as e:
            raise CuckooOperationalError("Option %s is not found in "
                                         "configuration, error: %s" %
                                         (section, e))

def parse_options(options):
    """Parse the analysis options field to a dictionary."""
    ret = {}
    for field in options.split(","):
        if "=" not in field:
            continue

        key, value = field.split("=", 1)
        ret[key.strip()] = value.strip()
    return ret

def emit_options(options):
    """Emit the analysis options from a dictionary to a string."""
    return ",".join("%s=%s" % (k, v) for k, v in options.items())
