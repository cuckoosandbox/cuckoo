import argparse
import os
import re
import socket
from uuid import uuid1

from stix2 import File, Bundle, Process, IPv4Address, IPv6Address, DomainName, Grouping, MalwareAnalysis

from cuckoo.common.abstracts import Report


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
	@staticmethod
	def ip2domain(ip):
		try:
			return ".".join(socket.gethostbyaddr(ip)[0].split(".")[-2:])
		except BaseException as e:
			return str(e)

	CWD = ""
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
			"prepare": lambda ob: Stix2.ip2domain(ob),
		},
	]

	@staticmethod
	def get_containerid(observable):
		regex = r"([0-9a-z]{4,30})[|]"
		if re.search(regex, observable):
			return re.search(regex, observable).group(1)
		return ""

	@staticmethod
	def is_on_whitelist(line):
		whitelist = [
			'/root/.npm/_cacache',  # npm cache
			'/root/.npm/_locks',  # npm locks
			'/root/.npm/anonymous-cli-metrics.json',  # npm metrics
			'/root/.npm/_logs',  # npm logs
		]

		return any([line.startswith(_) for _ in whitelist])

	@staticmethod
	def parse_observables_to_files(key, observables):
		list_of_stix_files = [
			File(
				type="file",
				id="file--" + str(uuid1()),
				name=stix_file.name,
				custom_properties={
					"container_id": stix_file.containerid,
					"timestamp": stix_file.timestamp,
					"full_output": stix_file.command,
				},
			)
			for stix_file in observables
		]
		return Grouping(
			type="grouping",
			name=key,
			context="suspicious-activity",
			object_refs=list_of_stix_files,
			allow_custom=True,
		), list_of_stix_files

	@staticmethod
	def parse_hosts_to_ip_mac_addresses(key, observables):
		ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
		list_of_stix_hosts = []
		for host in observables:
			if re.search(ip_regex, host.command):
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
		return Grouping(
			type="grouping",
			name=key,
			context="suspicious-activity",
			object_refs=list_of_stix_hosts,
			allow_custom=True,
		), list_of_stix_hosts

	@staticmethod
	def is_known_process(known_processes, process):
		for known in known_processes:
			if process.name == known.name:
				return True
		return False

	@staticmethod
	def parse_observables_to_processes(key, observables):
		list_of_stix_processes = []
		for process in observables:
			if not Stix2.is_known_process(list_of_stix_processes, process):
				list_of_stix_processes.append(Process(
					type="process",
					command_line=process.name,
					custom_properties={
						"container_id": process.containerid,
						"timestamp": process.timestamp,
						"name": process.name.split(" ")[-1],
					},
				))
		return Grouping(
			type="grouping",
			name=key,
			context="suspicious-activity",
			object_refs=list_of_stix_processes,
			allow_custom=True,
		), list_of_stix_processes

	@staticmethod
	def parse_observables_to_domains(key, observables):
		list_of_stix_domains = [
			DomainName(
				type="domain-name",
				value=domain.name,
				custom_properties={
					"container_id": domain.containerid,
					"timestamp": domain.timestamp,
					"process": domain.command,
				},
			)
			for domain in observables
		]
		return Grouping(
			type="grouping",
			name=key,
			context="suspicious-activity",
			object_refs=list_of_stix_domains,
			allow_custom=True,
		), list_of_stix_domains

	def run(self):
		global CWD
		global CLASSIFIERS
		parser = argparse.ArgumentParser(
			description='Parse system calls to observables.')
		parser.add_argument('stap',
							help='path to strace output')
		args = parser.parse_args()

		with open(args.stap, 'r') as stapfile:
			syscalls = stapfile.read()

		CWD = re.findall(r"execve\(.*?\"-c\", \"(.*?)\/.build", syscalls)[0]

		final = {}
		stix = {}
		for classifier in CLASSIFIERS:
			final[classifier['name']] = set()
			stix[classifier['name']] = set()

		for line in syscalls.splitlines():
			for classifier in CLASSIFIERS:
				name = classifier['name']
				for regex in classifier['regexes']:
					for observable in re.findall(regex, line):
						observable_name = classifier['prepare'](observable)
						new_ob = ObservableObject(observable_name, Stix2.get_containerid(line), line, line[:31])
						if new_ob.name and not Stix2.is_on_whitelist(new_ob.name):
							final[name].add(new_ob)

		for classifier in CLASSIFIERS:
			final[classifier["name"]] = sorted(list(final[classifier["name"]]))

		all_stix_groupings = []
		all_stix_objects = []
		for key, content in final.items():
			if key.startswith("files"):
				stix_grouping, stix_objects = Stix2.parse_observables_to_files(key, content)
				all_stix_groupings.append(stix_grouping)
				all_stix_objects.extend(stix_objects)
			elif key == "hosts_connected":
				stix_grouping, stix_objects = Stix2.parse_hosts_to_ip_mac_addresses(key, content)
				all_stix_groupings.append(stix_grouping)
				all_stix_objects.extend(stix_objects)
			elif key == "processes_created":
				stix_grouping, stix_objects = Stix2.parse_observables_to_processes(key, content)
				all_stix_groupings.append(stix_grouping)
				all_stix_objects.extend(stix_objects)
			elif key == "domains":
				stix_grouping, stix_objects = Stix2.parse_observables_to_domains(key, content)
				all_stix_groupings.append(stix_grouping)
				all_stix_objects.extend(stix_objects)
		stix_malware_analysis = MalwareAnalysis(
			type="malware-analysis",
			product="cuckoo-sandbox",
			analysis_sco_refs=all_stix_objects
		)
		all_stix_objects.append(stix_malware_analysis)
		all_stix_objects.extend(all_stix_groupings)
		stix_bundle = Bundle(type="bundle",
							 id="bundle--" + str(uuid1()),
							 objects=all_stix_objects,
							 allow_custom=True)
		output_file = open("stix-file.json", "w")
		output_file.writelines(str(stix_bundle))
		output_file.close()
































	def parse_syscalls_to_observable_objects(self, syscalls):

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
		

