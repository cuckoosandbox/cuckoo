import re
import socket
from uuid import uuid1

from stix2 import (
    File,
    Bundle,
    Process,
    IPv4Address,
    IPv6Address,
    DomainName,
    Grouping,
    MalwareAnalysis,
)

from cuckoo.common.abstracts import Report


class Stix2(Report):
    CWD = ""

    all_stix_objects = []
    processes = []
    files_read = []
    files_written = []
    files_removed = []
    ipv4 = []
    ipv6 = []
    domains = []
    classifiers = []
    key_words = []

    def run(self, results):
        self.init()
        syscalls = open(self.analysis_path + "/logs/all.stap", "r").read()
        self.CWD = self.find_execution_dir_of_build_script(syscalls)

        self.parse_syscalls_to_stix(syscalls)
        stix_malware_analysis = MalwareAnalysis(
            type="malware-analysis",
            product="cuckoo-sandbox",
            analysis_sco_refs=self.all_stix_objects,
        )
        self.all_stix_objects.append(stix_malware_analysis)

        self.add_stix_groupings()

        stix_bundle = Bundle(
            type="bundle",
            id="bundle--" + str(uuid1()),
            objects=self.all_stix_objects,
            allow_custom=True,
        )
        self.write_report(stix_bundle)

    def init(self):
        self.classifiers = [
            {
                "name": "files_removed",
                "key_word": ["unlink", "unlinkat", "rmdir"],
                "regexes": [
                    r"unlink\(\"(.*?)\"",
                    r"unlinkat\(.*?\"(.*?)\"",
                    r"rmdir\(\"(.*?)\"",
                ],
                "prepare": lambda ob: ob
                if ob.startswith("/")
                else self.CWD + "/" + str(ob),
            },
            {
                "name": "files_read",
                "key_word": ["openat"],
                "regexes": [
                    r"openat\(.*?\"(?P<filename>.*?)\".*?(?:O_RDWR|O_RDONLY).*?\)"
                ],
                "prepare": lambda ob: ob
                if ob.startswith("/")
                else self.CWD + "/" + str(ob),
            },
            {
                "name": "files_written",
                "key_word": ["openat", "rename", "link", "mkdir"],
                "regexes": [
                    r"openat\(.*?\"(.*?)\".*?(?:O_RDWR|O_WRONLY|O_CREAT|O_APPEND)",
                    r"(?:link|rename)\(\".*?\", \"(.*?)\"\)",
                    r"mkdir\(\"(.*?)\"",
                ],
                "prepare": lambda ob: ob
                if ob.startswith("/")
                else self.CWD + "/" + str(ob),
            },
            {
                "name": "hosts_connected",
                "key_word": ["connect"],
                "regexes": [r"connect\(.*?{AF_INET(?:6) i?, (.*?), (.*?)},"],
                "prepare": lambda ob: str(ob[0]) + ":" + str(ob[1]),
            },
            {
                "name": "processes_created",
                "key_word": ["execve"],
                "regexes": [r"execve\(.*?\[(.*?)\]"],
                "prepare": lambda ob: ob.replace('"', "").replace(",", ""),
            },
            {
                "name": "domains",
                "key_word": ["connect"],
                "regexes": [r"connect\(.*?{AF_INET(?:6)?, (.*?),"],
                "prepare": lambda ob: Stix2.ip2domain(ob),
            },
        ]
        self.key_words = [
            key_word
            for classifier in self.classifiers
            for key_word in classifier["key_word"]
        ]

    @staticmethod
    def find_execution_dir_of_build_script(syscalls):
        return re.findall(r"execve\(.*?\"-c\", \"(.*?)\/[^\"\/]+\"", syscalls)[0]

    def parse_syscalls_to_stix(self, syscalls):
        for classifier in self.classifiers:
            for regex in classifier["regexes"]:
                for line in syscalls.splitlines():
                    if self.line_is_relevant(line):
                        if re.search(regex, line):
                            self.parse_line_to_stix_object(classifier, line, regex)

    def line_is_relevant(self, line):
        for word in self.key_words:
            if word in line:
                return True

    def parse_line_to_stix_object(self, classifier, line, regex):
        if Stix2.is_on_whitelist(
            classifier["prepare"](re.search(regex, line).group(1))
        ):
            return ""
        if classifier["name"] == "processes_created":
            process = Process(
                type="process",
                command_line=classifier["prepare"](re.search(regex, line).group(1)),
                custom_properties={
                    "container_id": Stix2.get_containerid(line),
                    "timestamp": line[:31],
                    "full_output": line,
                    "executable_path": Stix2.get_executable_path(line),
                },
                allow_custom=True,
            )
            self.processes.append(process)
            self.all_stix_objects.append(process)
        if classifier["name"].startswith("files_"):
            file = File(
                type="file",
                id="file--" + str(uuid1()),
                name=classifier["prepare"](re.search(regex, line).group(1)),
                custom_properties={
                    "container_id": Stix2.get_containerid(line),
                    "timestamp": line[:31],
                    "full_output": line,
                },
                allow_custom=True,
            )
            self.all_stix_objects.append(file)
            if classifier["name"] == "files_removed":
                self.files_removed.append(file)
            if classifier["name"] == "files_written":
                self.files_written.append(file)
            if classifier["name"] == "files_read":
                self.files_read.append(file)
        if classifier["name"] == "hosts_connected":
            ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
            if re.search(ip_regex, line):
                ipv4 = IPv4Address(
                    type="ipv4-addr",
                    value=classifier["prepare"](re.search(regex, line).group(1)),
                    custom_properties={
                        "container_id": Stix2.get_containerid(line),
                        "timestamp": line[:31],
                        "full_output": line,
                    },
                    allow_custom=True,
                )
                self.ipv4.append(ipv4)
                self.all_stix_objects.append(ipv4)
            else:
                ipv6 = IPv6Address(
                    type="ipv6-addr",
                    value=classifier["prepare"](re.search(regex, line).group(1)),
                    custom_properties={
                        "container_id": Stix2.get_containerid(line),
                        "timestamp": line[:31],
                        "full_output": line,
                    },
                    allow_custom=True,
                )
                self.ipv6.append(ipv6)
                self.all_stix_objects.append(ipv6)
        if classifier["name"] == "domains":
            domain_name = classifier["prepare"](re.search(regex, line).group(1))
            if domain_name:
                domain = DomainName(
                    type="domain-name",
                    value=classifier["prepare"](re.search(regex, line).group(1)),
                    resolves_to_refs=[],
                    custom_properties={
                        "container_id": Stix2.get_containerid(line),
                        "timestamp": line[:31],
                        "full_output": line,
                    },
                    allow_custom=True,
                )
                self.domains.append(domain)
                self.all_stix_objects.append(domain)

    @staticmethod
    def is_on_whitelist(name):
        whitelist = [
            "/root/.npm/_cacache",  # npm cache
            "/root/.npm/_locks",  # npm locks
            "/root/.npm/anonymous-cli-metrics.json",  # npm metrics
            "/root/.npm/_logs",  # npm logs
        ]

        return any([name.startswith(_) for _ in whitelist])

    @staticmethod
    def get_containerid(line):
        regex = r"([0-9a-z]*)[|]"
        if re.search(regex, line):
            return re.search(regex, line).group(1)
        return ""

    @staticmethod
    def get_executable_path(line):
        regex_for_executable_name = r"execve\(\"([^\"]*)\""
        search_result = re.search(regex_for_executable_name, line)
        if not search_result:
            return "Exec path not found."
        return search_result.group(1)

    @staticmethod
    def ip2domain(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except BaseException:
            return ""

    def add_stix_groupings(self):
        if self.processes:
            self.all_stix_objects.append(
                Grouping(
                    type="grouping",
                    name="processes_created",
                    context="suspicious-activity",
                    object_refs=self.processes,
                )
            )
        if self.files_read:
            self.all_stix_objects.append(
                Grouping(
                    type="grouping",
                    name="files_read",
                    context="suspicious-activity",
                    object_refs=self.files_read,
                )
            )
        if self.files_written:
            self.all_stix_objects.append(
                Grouping(
                    type="grouping",
                    name="files_written",
                    context="suspicious-activity",
                    object_refs=self.files_written,
                )
            )
        if self.files_removed:
            self.all_stix_objects.append(
                Grouping(
                    type="grouping",
                    name="files_removed",
                    context="suspicious-activity",
                    object_refs=self.files_removed,
                )
            )
        if self.ipv4 or self.ipv6:
            self.all_stix_objects.append(
                Grouping(
                    type="grouping",
                    name="hosts_connected",
                    context="suspicious-activity",
                    object_refs=self.ipv4.extend(self.ipv6),
                )
            )
        if self.domains:
            self.all_stix_objects.append(
                Grouping(
                    type="grouping",
                    name="domains",
                    context="suspicious-activity",
                    object_refs=self.domains,
                )
            )

    def write_report(self, stix_bundle):
        output_file = open(self.analysis_path + "/stix-file.json", "w")
        str_bundle = stix_bundle.serialize(pretty=False, indent=4)
        output_file.writelines(str_bundle)
        output_file.close()
