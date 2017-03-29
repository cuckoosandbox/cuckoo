#!/usr/bin/env python
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import grp
import json
import logging
import os.path
import re
import socket
import stat
import subprocess
import sys

def run(*args):
    """Wrapper to Popen."""
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return stdout, stderr

def nic_available(interface):
    """Check if specified network interface is available."""
    try:
        subprocess.check_call([settings.ifconfig, interface],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False

def rt_available(rt_table):
    """Check if specified routing table is defined."""
    try:
        subprocess.check_call([settings.ip, "route", "list", "table", rt_table],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False

def vpn_status():
    """Gets current VPN status."""
    ret = {}
    for line in run(settings.service, "openvpn", "status")[0].split("\n"):
        x = re.search("'(?P<vpn>\\w+)'\\ is\\ (?P<running>not)?", line)
        if x:
            ret[x.group("vpn")] = x.group("running") != "not"

    return ret

def vpn_enable(name):
    """Start a VPN."""
    run(settings.service, "openvpn", "start", name)

def vpn_disable(name):
    """Stop a running VPN."""
    run(settings.service, "openvpn", "stop", name)

def forward_drop():
    """Disable any and all forwarding unless explicitly said so."""
    run(settings.iptables, "-P", "FORWARD", "DROP")

def enable_nat(interface):
    """Enable NAT on this interface."""
    run(settings.iptables, "-t", "nat", "-A", "POSTROUTING",
        "-o", interface, "-j", "MASQUERADE")

def disable_nat(interface):
    """Disable NAT on this interface."""
    while not run(settings.iptables, "-t", "nat", "-D", "POSTROUTING",
                  "-o", interface, "-j", "MASQUERADE")[1]:
        pass

def init_rttable(rt_table, interface):
    """Initialise routing table for this interface using routes
    from main table."""
    if rt_table in ["local", "main", "default"]:
        return

    stdout, _ = run(settings.ip, "route", "list", "dev", interface)
    for line in stdout.split("\n"):
        args = ["route", "add"] + [x for x in line.split(" ") if x]
        args += ["dev", interface, "table", rt_table]
        run(settings.ip, *args)

def flush_rttable(rt_table):
    """Flushes specified routing table entries."""
    if rt_table in ["local", "main", "default"]:
        return

    run(settings.ip, "route", "flush", "table", rt_table)

def forward_enable(src, dst, ipaddr):
    """Enable forwarding a specific IP address from one interface into
    another."""
    run(settings.iptables, "-A", "FORWARD", "-i", src, "-o", dst,
        "--source", ipaddr, "-j", "ACCEPT")

    run(settings.iptables, "-A", "FORWARD", "-i", dst, "-o", src,
        "--destination", ipaddr, "-j", "ACCEPT")

def forward_disable(src, dst, ipaddr):
    """Disable forwarding of a specific IP address from one interface into
    another."""
    run(settings.iptables, "-D", "FORWARD", "-i", src, "-o", dst,
        "--source", ipaddr, "-j", "ACCEPT")

    run(settings.iptables, "-D", "FORWARD", "-i", dst, "-o", src,
        "--destination", ipaddr, "-j", "ACCEPT")

def srcroute_enable(rt_table, ipaddr):
    """Enable routing policy for specified source IP address."""
    run(settings.ip, "rule", "add", "from", ipaddr, "table", rt_table)
    run(settings.ip, "route", "flush", "cache")

def srcroute_disable(rt_table, ipaddr):
    """Disable routing policy for specified source IP address."""
    run(settings.ip, "rule", "del", "from", ipaddr, "table", rt_table)
    run(settings.ip, "route", "flush", "cache")

handlers = {
    "nic_available": nic_available,
    "rt_available": rt_available,
    "vpn_status": vpn_status,
    "vpn_enable": vpn_enable,
    "vpn_disable": vpn_disable,
    "forward_drop": forward_drop,
    "enable_nat": enable_nat,
    "disable_nat": disable_nat,
    "init_rttable": init_rttable,
    "flush_rttable": flush_rttable,
    "forward_enable": forward_enable,
    "forward_disable": forward_disable,
    "srcroute_enable": srcroute_enable,
    "srcroute_disable": srcroute_disable,
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("socket", nargs="?", default="/tmp/cuckoo-rooter",
                        help="Unix socket path")
    parser.add_argument("-g", "--group", default="cuckoo",
                        help="Unix socket group")
    parser.add_argument("--ifconfig", default="/sbin/ifconfig",
                        help="Path to ifconfig")
    parser.add_argument("--service", default="/usr/sbin/service",
                        help="Service wrapper script for invoking OpenVPN")
    parser.add_argument("--iptables", default="/sbin/iptables",
                        help="Path to iptables")
    parser.add_argument("--ip", default="/sbin/ip", help="Path to ip")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose logging")
    settings = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger("cuckoo-rooter")

    if not settings.service or not os.path.exists(settings.service):
        sys.exit(
            "The service binary is not available, please configure it!\n"
            "Note that on CentOS you should provide --service /sbin/service, "
            "rather than using the Ubuntu/Debian default /usr/sbin/service."
        )

    if not settings.ifconfig or not os.path.exists(settings.ifconfig):
        sys.exit("The `ifconfig` binary is not available, eh?!")

    if not settings.iptables or not os.path.exists(settings.iptables):
        sys.exit("The `iptables` binary is not available, eh?!")

    if os.getuid():
        sys.exit("This utility is supposed to be ran as root.")

    if os.path.exists(settings.socket):
        os.remove(settings.socket)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind(settings.socket)

    # Provide the correct file ownership and permission so Cuckoo can use it
    # from an unprivileged process, based on Sean Whalen's routetor.
    try:
        gr = grp.getgrnam(settings.group)
    except KeyError:
        sys.exit(
            "The group (`%s`) does not exist. Please define the group / user "
            "through which Cuckoo will connect to the rooter, e.g., "
            "./utils/rooter.py -g myuser" % settings.group
        )

    os.chown(settings.socket, 0, gr.gr_gid)
    os.chmod(settings.socket, stat.S_IRUSR | stat.S_IWUSR | stat.S_IWGRP)

    while True:
        command, addr = server.recvfrom(4096)

        try:
            obj = json.loads(command)
        except:
            log.info("Received invalid request: %r", command)
            continue

        command = obj.get("command")
        args = obj.get("args", [])
        kwargs = obj.get("kwargs", {})

        if not isinstance(command, basestring) or command not in handlers:
            log.info("Received incorrect command: %r", command)
            continue

        if not isinstance(args, (tuple, list)):
            log.info("Invalid arguments type: %r", args)
            continue

        if not isinstance(kwargs, dict):
            log.info("Invalid keyword arguments: %r", kwargs)
            continue

        for arg in args + kwargs.keys() + kwargs.values():
            if not isinstance(arg, basestring):
                log.info("Invalid argument detected: %r", arg)
                break
        else:
            if settings.verbose:
                log.info(
                    "Processing command: %s %s %s", command,
                    " ".join(args),
                    " ".join("%s=%s" % (k, v) for k, v in kwargs.items())
                )

            output = e = None
            try:
                output = handlers[command](*args, **kwargs)
            except Exception as e:
                log.exception("Error executing command")

            server.sendto(json.dumps({
                "output": output,
                "exception": str(e) if e else None,
            }), addr)
