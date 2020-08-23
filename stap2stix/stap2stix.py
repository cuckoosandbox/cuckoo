#!/usr/bin/env python3

import argparse
import re
import socket
from pathlib import Path
from uuid import uuid1

from stix2 import File, Process, DomainName, Bundle, IPv4Address, IPv6Address


class ObservableObject:
    def __init__(self, name, containerid, timestamp):
        self.name = name
        self.containerid = containerid
        self.timestamp = timestamp

    def __lt__(self, other):
        if self.name < other.name:
            return True
        return False

    def __eq__(self, other):
        if isinstance(other, list):
            return False
        if self.name != other.name or self.container_id != other.container_id:
            return False
        return True


CWD = ""
CLASSIFIERS = [
    {
        "name": "files_removed",
        "regexes": [
            r"unlink\(\"(.*?)\"",
            r"unlinkat\(.*?\"(.*?)\"",
            r"rmdir\(\"(.*?)\"",
        ],
        "prepare": lambda ob: ob if ob.startswith("/") else f"{CWD}/{ob}",
    },
    {
        "name": "files_read",
        "regexes": [r"openat\(.*?\"(?P<filename>.*?)\".*?(?:O_RDWR|O_RDONLY).*?\)"],
        "prepare": lambda ob: ob if ob.startswith("/") else f"{CWD}/{ob}",
    },
    {
        "name": "files_written",
        "regexes": [
            r"openat\(.*?\"(.*?)\".*?(?:O_RDWR|O_WRONLY|O_CREAT|O_APPEND)",
            r"(?:link|rename)\(\".*?\", \"(.*?)\"\)",
            r"mkdir\(\"(.*?)\"",
        ],
        "prepare": lambda ob: ob if ob.startswith("/") else f"{CWD}/{ob}",
    },
    {
        "name": "hosts_connected",
        "regexes": [r"connect\(.*?{AF_INET(?:6) i?, (.*?), (.*?)},"],
        "prepare": lambda ob: f"{ob[0]}:{ob[1]}",
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


def main():
    global CWD

    args = parse_arguments()

    with open(args.stapfile, "r") as stapfile:
        syscalls = stapfile.read()

    CWD = re.findall(r"execve\(.*?\"-c\", \"(.*?)\/.build", syscalls)[0]

    observables = {}
    for classifier in CLASSIFIERS:
        observables[classifier["name"]] = []

    for line in syscalls.split("\n"):
        for classifier in CLASSIFIERS:
            name = classifier["name"]

            for regex in classifier["regexes"]:
                if re.search(regex, line):
                    new_ob = ObservableObject(
                        classifier["prepare"](line), get_container_id(line), line[:31]
                    )
                    if new_ob not in observables[name] and not is_on_whitelist(
                        new_ob.name
                    ):
                        observables[name].append(new_ob)

    for key in observables.keys():
        observables[key] = sorted(observables[key])

    parse_to_stix(observables)


def get_container_id(observable):
    regex = r"([0-9a-z]{4,30})[|]"
    if re.search(regex, observable):
        return re.search(regex, observable).group(1)
    return ""


def parse_arguments():
    parser = argparse.ArgumentParser(description="Parse system calls to STIX2 objects.")
    parser.add_argument(
        "stapfile", help="Systemtap file containing the analysis from Cuckoo Sandbox."
    )
    args = parser.parse_args()
    return args


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


def ip2domain(ip):
    try:
        return ".".join(socket.gethostbyaddr(ip)[0].split(".")[-2:])
    except BaseException:
        return ""


def parse_to_stix(observables):
    for key, data in observables.items():
        if key.startswith("files"):
            stix_bundle = parse_observables_to_files(data)
        elif key == "hosts_connected":
            stix_bundle = parse_hosts_to_ip_mac_addresses(data)
        elif key == "processes_created":
            stix_bundle = parse_observables_to_processes(data)
        elif key == "domains":
            stix_bundle = parse_observables_to_domains(data)
        output_file = Path(__file__).with_name(f"{key}.stix")
        output_file.write_text(str(stix_bundle))


def parse_observables_to_files(observables):
    list_of_stix_files = [
        File(
            type="file",
            name=file.name,
            custom_properties={
                "container_id": file.container_id,
                "timestamp": file.timestamp,
            },
        )
        for file in observables
    ]
    stix_bundle = Bundle(
        type="bundle",
        id=f"bundle--{uuid1()}",
        objects=list_of_stix_files,
        allow_custom=True,
    )
    return stix_bundle


def parse_hosts_to_ip_mac_addresses(observables):
    ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
    list_of_stix_hosts = []
    for host in observables:
        if re.search(ip_regex, host):
            stix_ip = IPv4Address(
                type="ipv4-addr",
                value=host.name,
                custom_properties={
                    "container_id": host.container_id,
                    "timestamp": host.timestamp,
                },
            )
        else:
            stix_ip = IPv6Address(
                type="ipv6-addr",
                value=host.name,
                custom_properties={
                    "container_id": host.container_id,
                    "timestamp": host.timestamp,
                },
            )
        list_of_stix_hosts.append(stix_ip)
    stix_bundle = Bundle(
        type="bundle",
        id=f"bundle--{uuid1()}",
        objects=list_of_stix_hosts,
        allow_custom=True,
    )
    return stix_bundle


def parse_observables_to_processes(observables):
    list_of_stix_process = [
        Process(
            type="process",
            command_line=process.name,
            custom_properties={
                "container_id": process.container_id,
                "timestamp": process.timestamp,
            },
        )
        for process in observables
    ]
    return Bundle(
        type="bundle",
        id=f"bundle--{uuid1()}",
        objects=list_of_stix_process,
        allow_custom=True,
    )


def parse_observables_to_domains(observables):
    list_of_stix_domains = [
        DomainName(
            type="domain-name",
            value=domain.name,
            custom_properties={
                "container_id": domain.container_id,
                "timestamp": domain.timestamp,
            },
        )
        for domain in observables
    ]
    return Bundle(
        type="bundle",
        id=f"bundle--{uuid1()}",
        objects=list_of_stix_domains,
        allow_custom=True,
    )


if __name__ == "__main__":
    main()
