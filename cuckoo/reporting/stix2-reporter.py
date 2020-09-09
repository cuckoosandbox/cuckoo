import os
import argparse
import re
import socket
from uuid import uuid1
from stix2 import File, Bundle, Process, IPv4Address, IPv6Address, DomainName

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooReportError

class ObservableObject:
    def __init__(self, name, containerid, command, timestamp):
        self.name = name
        self.containerid = containerid
        self.command = command
        self.timestamp = timestamp

    def __lt__(self, other):
        if self.name < other.name:
            return True
        return False

    def __eq__(self, other):
        if isinstance(other, list):
            return False
        if self.name != other.name or self.containerid != other.containerid:
            return False
        return True
        
class Stix2(Report):
	CWD = ""

	def ip2domain(ip):
		try:
			return ".".join(socket.gethostbyaddr(ip)[0].split(".")[-2:])
		except BaseException as e:
			return str(e)


	def parse_syscalls_to_observable_objects(self, syscalls):
		CLASSIFIERS = [
			{
				"name": "files_removed",
				"regexes": [
				    r"unlink\(\"(.*?)\"",
				    r"unlinkat\(.*?\"(.*?)\"",
				    r"rmdir\(\"(.*?)\"",
				],
				"prepare": lambda ob: ob if ob.startswith("/") else CWD + "/" + str(ob),
			},
			{
				"name": "files_read",
				"regexes": [r"openat\(.*?\"(?P<filename>.*?)\".*?(?:O_RDWR|O_RDONLY).*?\)"],
				"prepare": lambda ob: ob if ob.startswith("/") else CWD + "/" + str(ob),
			},
			{
				"name": "files_written",
				"regexes": [
				    r"openat\(.*?\"(.*?)\".*?(?:O_RDWR|O_WRONLY|O_CREAT|O_APPEND)",
				    r"(?:link|rename)\(\".*?\", \"(.*?)\"\)",
				    r"mkdir\(\"(.*?)\"",
				],
				"prepare": lambda ob: ob if ob.startswith("/") else CWD + "/" + str(ob),
			},
			{
				"name": "hosts_connected",
				"regexes": [r"connect\(.*?{AF_INET(?:6) i?, (.*?), (.*?)},"],
				"prepare": lambda ob: str(ob[0]) + ":" + str(ob[1]),
			},
			{
				"name": "processes_created",
				"regexes": [r"execve\(.*?\[(.*?)\]"],
				"prepare": lambda ob: ob.replace('"', "").replace(",", ""),
			},
			{
				"name": "domains",
				"regexes": [r"connect\(.*?{AF_INET(?:6)?, (.*?),"],
				"prepare": lambda ob: ip2domain(ob),
			},
		]
		observables = {}
		for classifier in CLASSIFIERS:
		    observables[classifier["name"]] = []

		for line in syscalls:
		    for classifier in CLASSIFIERS:
		        name = classifier["name"]
		        for regex in classifier["regexes"]:
		            if re.search(regex, line):
		                new_ob = ObservableObject(
		                    self.get_name(line, name), self.get_containerid(line), classifier["prepare"](line), line[:31]
		                )
		                if new_ob not in observables[name] and not self.is_on_whitelist(
		                        new_ob.command
		                ):
		                    observables[name].append(new_ob)
		for key in observables.keys():
		    observables[key] = sorted(observables[key])
		return observables

	@staticmethod
	def get_syscalls_and_cwd(stapfile):
		syscalls = stapfile.read()
		CWD = re.findall(r"execve\(.*?\"-c\", \"(.*?)\/.build", syscalls)[0]
		return syscalls.split("\n"), CWD

	@staticmethod
	def get_name(line, classifier):
		if classifier == "processes_created" or classifier == "domains":
		    start = line.find("|") + 1
		    end = line.find("@")
		    return line[start:end]
		elif "files" in classifier:
		    start = line.find('"') + 1
		    end = line[start:].find('"') + start
		    return line[start:end]
		else:
		    return line

	@staticmethod
	def get_containerid(observable):
		regex = r"([0-9a-z]{4,30})[|]"
		if re.search(regex, observable):
		    return re.search(regex, observable).group(1)
		return ""

	@staticmethod
	def is_on_whitelist(line):
		whitelist = [
		    "/root/.npm/_cacache",  # npm cache
		    "/root/.npm/_locks",  # npm locks
		    "/root/.npm/anonymous-cli-metrics.json",  # npm metrics
		    "/root/.npm/_logs",  # npm logs
		]
		for w in whitelist:
		    if w in line:
		        return True
		return False


	def parse_to_stix(self, observables):
		os.mkdir(os.path.join(self.analysis_path, "stix"))
		for key, data in observables.items():
		    stix_bundle = "Unable to parse '" + key + "' observables to STIX2."
		    if key.startswith("files"):
		        stix_bundle = self.parse_observables_to_files(data, key)
		    elif key == "hosts_connected":
		        stix_bundle = self.parse_hosts_to_ip_mac_addresses(data, key)
		    elif key == "processes_created":
		        stix_bundle = self.parse_observables_to_processes(data, key)
		    elif key == "domains":
		        stix_bundle = self.parse_observables_to_domains(data, key)
		    output_file = open(self.analysis_path + "/stix/" + key + ".stix", "w")
		    output_file.write(stix_bundle)
		    output_file.close()

	@staticmethod
	def parse_observables_to_files(observables, key):
		list_of_stix_files = [
		    File(
		        type="file",
		        id="file--" + str(uuid1()),
		        name=file.name,
		        custom_properties={
		            "container_id": file.containerid,
		            "timestamp": file.timestamp,
		            "full_output": file.command,
		        },
		    )
		    for file in observables
		]
		return str(Bundle(
        	type="bundle",
        	id="bundle--" + str(uuid1()),
        	objects=list_of_stix_files,
       		allow_custom=True,
    	))

	@staticmethod
	def parse_hosts_to_ip_mac_addresses(observables, key):
		ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
		list_of_stix_hosts = []
		for host in observables:
		    if re.search(ip_regex, host):
		        stix_ip = IPv4Address(
		            type="ipv4-addr",
		            value=host.name,
		            custom_properties={
		                "container_id": host.containerid,
		                "timestamp": host.timestamp,
		            },
		        )
		    else:
		        stix_ip = IPv6Address(
		            type="ipv6-addr",
		            value=host.name,
		            custom_properties={
		                "container_id": host.containerid,
		                "timestamp": host.timestamp,
		            },
		        )
		    list_of_stix_hosts.append(stix_ip)
		return str(Bundle(
        	type="bundle",
        	id="bundle--" + str(uuid1()),
        	objects=list_of_stix_hosts,
       		allow_custom=True,
    	))

	def parse_observables_to_processes(self, observables, key):
		list_of_stix_processes = [
		    Process(
		        type="process",
		        command_line=process.command,
		        custom_properties={
		            "container_id": process.containerid,
		            "timestamp": process.timestamp,
		            "name": process.name,
		        },
		    )
		    for process in observables
		]
		return str(Bundle(
        	type="bundle",
        	id="bundle--" + str(uuid1()),
        	objects=list_of_stix_processes,
       		allow_custom=True,
    	))
    	
	@staticmethod
	def parse_observables_to_domains(observables, key):
		list_of_stix_domains = [
		    DomainName(
		        type="domain-name",
		        value=domain.command,
		        custom_properties={
		            "container_id": domain.containerid,
		            "timestamp": domain.timestamp,
		            "process": domain.name,
		        },
		    )
		    for domain in observables
		]		
		return str(Bundle(
        	type="bundle",
        	id="bundle--" + str(uuid1()),
        	objects=list_of_stix_domains,
       		allow_custom=True,
    	))
	
	def run(self, results):
		global CWD
		stap_file = open(self.analysis_path + "/logs/all.stap", "r")
		syscalls, CWD = self.get_syscalls_and_cwd(stap_file)
		observables = self.parse_syscalls_to_observable_objects(syscalls)
		self.parse_to_stix(observables)
		

