# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ConfigParser
import os
import logging
import click

from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.common.objects import Dictionary
from cuckoo.misc import cwd

log = logging.getLogger(__name__)

class Config:
    """Configuration file parser."""

    # Config Parameters and their types
    BOOLEAN,STRING,INT,PATH,IP,UUID = range(6)
    ParamTypes = {
        ## cuckoo.conf parameters
        'cuckoo' : {
            'cuckoo' : {
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
            },
            'resultserver' : {
                'ip':IP,
                'port':INT,
                'force_port':BOOLEAN,
                'upload_max_size':INT,
            },
            'processing' : {
                'analysis_size_limit':INT,
                'resolve_dns':BOOLEAN,
                'sort_pcap':BOOLEAN,
            },
            'database' : {
                'connection':STRING,
                'timeout':INT,
            },
            'timeouts' : {
                'default':INT,
                'critical':INT,
                'vm_state':INT,
            },
        },
        ## virtualbox.conf parameters
        'virtualbox' : {
            'virtualbox' : {
                'mode': STRING,
                'path':PATH,
                'interface':STRING,
                'machines':STRING,
            },
            '*' : {
                'label':STRING,
                'platform':STRING,
                'ip': IP,
                'snapshot':STRING,
                'interface': STRING,
                'resultserver_ip':IP,
                'resultserver_port':INT,
                'tags':STRING,
            },
            'honeyd' : {
                'label': STRING,
                'platform': STRING,
                'ip': IP,
                'tags': STRING,
                'options':STRING,
            },
        },
        ## auxiliary.conf parameters
        'auxiliary' : {
            'sniffer' : {
                'enabled':BOOLEAN,
                'tcpdump':PATH,
                'bpf': STRING,
            },
            'mitm' : {
                'enabled': BOOLEAN,
                'mitmdump':PATH,
                'port_base':INT,
                'script':PATH,
                'certificate':PATH,
            },
            'services' : {
                'enabled': BOOLEAN,
                'services':STRING,
                'timeout': INT,
            },
            'reboot' : {
                'enabled': BOOLEAN,
            },
        },
        ## avd.conf parameters
        'avd' : {
            'avd' : {
                'mode': STRING,
                'emulator_path':PATH,
                'adb_path': PATH,
                'avd_path': PATH,
                'reference_machine':STRING,
                'machines': STRING,
            },
            '*' : {
                'label': STRING,
                'platform': STRING,
                'ip': IP,
                'emulator_port':INT,
                'resultserver_ip': IP,
                'resultserver_port': INT,
            },
        },
        ## esx.conf parameters
        'esx' : {
            'esx': {
                'dsn':STRING,
                'username':STRING,
                'password':STRING,
                'machines': STRING,
                'interface': STRING,
            },
            '*' : {
                'label': STRING,
                'platform': STRING,
                'ip': IP,
                'snapshot': STRING,
                'interface': STRING,
                'resultserver_ip': IP,
                'resultserver_port': INT,
                'tags': STRING,
            },
        },
        ## kvm.conf parameters
        'kvm' : {
            'kvm' : {
                'machines': STRING,
                'interface': STRING,
            },
            '*' : {
                'label': STRING,
                'platform': STRING,
                'ip': IP,
                'snapshot': STRING,
                'interface': STRING,
                'resultserver_ip': IP,
                'resultserver_port': INT,
                'tags': STRING,
            },
        },
        ## memory.conf parameters
        'memory' : {
            'basic' : {
                'guest_profile':STRING,
                'delete_memdump':STRING,
                'filter':BOOLEAN,
            },
            'malfind' : {
                'enabled': BOOLEAN,
                'filter': BOOLEAN,
            },
            'apihooks': {
                'enabled': BOOLEAN,
                'filter': BOOLEAN,
            },
            'pslist': {
                'enabled': BOOLEAN,
                'filter': BOOLEAN,
            },
            'psxview': {
                'enabled': BOOLEAN,
                'filter': BOOLEAN,
            },
            'callbacks': {
                'enabled': BOOLEAN,
                'filter': BOOLEAN,
            },
            'idt': {
                'enabled': BOOLEAN,
                'filter': BOOLEAN,
            },
            'timers': {
                'enabled': BOOLEAN,
                'filter': BOOLEAN,
            },
            'messagehooks': {
                'enabled': BOOLEAN,
                'filter': BOOLEAN,
            },
            'getsids': {
                'enabled': BOOLEAN,
                'filter': BOOLEAN,
            },
            'privs': {
                'enabled': BOOLEAN,
                'filter': BOOLEAN,
            },
            'dlllist': {
                'enabled': BOOLEAN,
                'filter': BOOLEAN,
            },
            'handles' : {
                'enabled': BOOLEAN,
                'filter': BOOLEAN,
            },
            'ldrmodules' : {
                'enabled': BOOLEAN,
                'filter': BOOLEAN,
            },
            'mutantscan': {
                'enabled': BOOLEAN,
                'filter': BOOLEAN,
            },
            'devicetree' : {
                'enabled': BOOLEAN,
                'filter': BOOLEAN,
            },
            'svcscan': {
                'enabled': BOOLEAN,
                'filter': BOOLEAN,
            },
            'modscan' : {
                'enabled': BOOLEAN,
                'filter': BOOLEAN,
            },
            'yarascan': {
                'enabled': BOOLEAN,
                'filter': BOOLEAN,
            },
            'ssdt': {
                'enabled': BOOLEAN,
                'filter': BOOLEAN,
            },
            'gdt' : {
                'enabled': BOOLEAN,
                'filter': BOOLEAN,
            },
            'sockscan' : {
                'enabled': BOOLEAN,
                'filter': BOOLEAN,
            },
            'netscan' : {
                'enabled': BOOLEAN,
                'filter': BOOLEAN,
            },
            'mask' : {
                'enabled': BOOLEAN,
                'pid_generic':STRING,
            },
        },
        ## physical.conf parameters
        'physical' : {
            'physical' : {
                'machines': STRING,
                'user':STRING,
                'password': STRING,
                'interface': STRING,
            },
            'fog' : {
                'hostname':STRING,
                'username': STRING,
                'password': STRING,
            },
            '*' : {
                'label': STRING,
                'platform': STRING,
                'ip': IP,
            },
        },
        ## processing.conf parameters
        'processing' : {
            'analysisinfo' : {
                'enabled': BOOLEAN,
            },
            'apkinfo' : {
                'enabled': BOOLEAN,
                'decompilation_threshold': INT,
            },
            'baseline': {
                'enabled': BOOLEAN,
            },
            'behavior': {
                'enabled': BOOLEAN,
            },
            'buffer': {
                'enabled': BOOLEAN,
            },
            'debug': {
                'enabled': BOOLEAN,
            },
            'droidmon': {
                'enabled': BOOLEAN,
            },
            'dropped': {
                'enabled': BOOLEAN,
            },
            'dumptls': {
                'enabled': BOOLEAN,
            },
            'googleplay': {
                'enabled': BOOLEAN,
                'android_id': STRING,
                'google_login': STRING,
                'google_password': STRING,
            },
            'memory': {
                'enabled': BOOLEAN,
            },
            'misp': {
                'enabled': BOOLEAN,
                'url': STRING,
                'apikey': STRING,
                'maxioc': INT,
            },
            'network': {
                'enabled': BOOLEAN,
            },
            'procmemory': {
                'enabled': BOOLEAN,
                'idapro': BOOLEAN,
                'extract_img': BOOLEAN,
                'dump_delete': BOOLEAN,
            },
            'procmon': {
                'enabled': BOOLEAN,
            },
            'screenshots': {
                'enabled': BOOLEAN,
                'tesseract': BOOLEAN,
            },
            'snort': {
                'enabled': BOOLEAN,
                'snort': PATH,
                'conf': PATH,
            },
            'static': {
                'enabled': BOOLEAN,
            },
            'strings': {
                'enabled': BOOLEAN,
            },
            'suricata': {
                'enabled': BOOLEAN,
                'suricata': PATH,
                'eve_log': PATH,
                'files_log': PATH,
                'files_dir': PATH,
                'socket': PATH,
            },
            'targetinfo': {
                'enabled': BOOLEAN,
            },
            'virustotal': {
                'enabled': BOOLEAN,
                'timeout': INT,
                'scan': BOOLEAN,
                'key': STRING,
            },
            'irma' : {
                'enabled': BOOLEAN,
                'force':BOOLEAN,
                'timeout': INT,
                'scan': BOOLEAN,
                'url' : STRING,
            },
        },
        ## qemu.conf parameters
        'qemu' : {
            'qemu' : {
                'path': PATH,
                'interface': STRING,
                'machines': STRING,
            },
            '*' : {
                'label': STRING,
                'image': PATH,
                'arch': STRING,
                'platform': STRING,
                'ip': IP,
                'interface': STRING,
                'resultserver_ip': IP,
                'resultserver_port': INT,
                'tags': STRING,
                'kernel_path':PATH,
            },
        },
        ## reporting.conf parameters
        'reporting' : {
            'jsondump' : {
                'enabled': BOOLEAN,
                'indent': INT,
                'encoding': STRING,
                'calls': BOOLEAN,
            },
            'reporthtml' : {
                'enabled': BOOLEAN,
            },
            'misp' : {
                'enabled': BOOLEAN,
                'url': STRING,
                'apikey': STRING,
                'mode': STRING,
            },
            'mongodb' : {
                'enabled': BOOLEAN,
                'host' : IP,
                'port' : INT,
                'db' : STRING,
                'store_memdump' : BOOLEAN,
                'paginate' : INT,
            },
            'elasticsearch' : {
                'enabled': BOOLEAN,
                'hosts': STRING,
                'calls': BOOLEAN,
                'index': STRING,
                'index_time_pattern': STRING,
            },
            'moloch' : {
                'enabled': BOOLEAN,
                'host': IP,
                'moloch_capture': PATH,
                'conf': PATH,
                'instance': STRING,
            },
            'notification' : {
                'enabled': BOOLEAN,
                'url': STRING,
                'identifier':STRING,
            },
        },
        ## routing.conf parameters
        'routing' : {
            'routing' : {
                'route': STRING,
                'internet': STRING,
                'rt_table': STRING,
                'auto_rt': BOOLEAN,
                'drop': BOOLEAN,
            },
            'inetsim' : {
                'enabled': BOOLEAN,
                'server': IP,
            },
            'tor' : {
                'enabled': BOOLEAN,
                'dnsport': INT,
                'proxyport': INT,
            },
            'vpn' : {
                'enabled': BOOLEAN,
                'vpns': STRING,
            },
            '*' : {
                'name':STRING,
                'description':STRING,
                'interface': STRING,
                'rt_table': STRING,
            },
        },
        ## vmware.conf parameters
        'vmware' : {
            'vmware' : {
                'mode': STRING,
                'path': PATH,
                'interface': STRING,
                'machines': STRING,
            },
            '*': {
                'vmx_path': PATH,
                'snapshot' : STRING,
                'platform': STRING,
                'ip': IP,
                'interface': STRING,
                'resultserver_ip': IP,
                'resultserver_port': INT,
                'tags': STRING,
            },
        },
        ## vsphere.conf parameters
        'vsphere': {
            'vsphere': {
                'host': IP,
                'port': INT,
                'user': STRING,
                'pwd': STRING,
                'interface': STRING,
                'machines': STRING,
                'unverified_ssl': BOOLEAN,
            },
            '*': {
                'label': STRING,
                'platform': STRING,
                'ip': IP,
                'interface': STRING,
                'resultserver_ip': IP,
                'resultserver_port': INT,
                'tags': STRING,
            },
        },
        ## xenserver.conf parameters
        'xenserver': {
            'xenserver': {
                'user': STRING,
                'password': STRING,
                'url':STRING,
                'interface': STRING,
                'machines': STRING,
            },
            '*': {
                'uuid': UUID,
                'snapshot': STRING,
                'platform': STRING,
                'ip': IP,
                'interface': STRING,
                'resultserver_ip': IP,
                'resultserver_port': INT,
                'tags': STRING,
            },
        },
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

        if file_name not in self.ParamTypes:
            log.error("Unknown config file %s.conf" % (file_name))
            return
        for section in config.sections():
            if section in self.ParamTypes[file_name]:
                sectionTypes = self.ParamTypes[file_name][section]
            ## Hacky fix to get the type of unknown sections
            elif '*' in self.ParamTypes[file_name]:
                sectionTypes = self.ParamTypes[file_name]['*']
            else:
                log.error("Config section %s NOT FOUND!!" % (section))
                continue
            setattr(self, section, Dictionary())
            for name, raw_value in config.items(section):
                if name in sectionTypes:
                    value = ''
                    if sectionTypes[name] in [self.STRING, self.IP]:
                        value = config.get(section,name)
                    elif sectionTypes[name] is self.PATH:
                        try:
                            c = click.Path()
                            value = c.convert(config.get(section,name),None,None)
                        except Exception as ex:
                            log.error("Incorrect Path : %s , Error : %s",
                                      config.get(section,name),ex)
                    elif sectionTypes[name] is self.UUID:
                        try:
                            c = click.UUID(config.get(section,name))
                            value = str(c)
                        except Exception as ex:
                            log.error("Incorrect UUID %s",config.get(section, name))
                    elif sectionTypes[name] is self.INT:
                        try:
                            value = config.getint(section,name)
                        except ValueError:
                            value = config.get(section,name)
                    elif sectionTypes[name] is self.BOOLEAN:
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
