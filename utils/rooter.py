#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
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

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.config import Config

def run(*args):
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return stdout, stderr

def nic_available(interface):
    try:
        subprocess.check_call([settings.ifconfig, interface],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False

def vpn_status():
    ret = {}
    for line in run(settings.openvpn, "status")[0].split("\n"):
        x = re.search("'(?P<vpn>\\w+)'\\ is\\ (?P<running>not)?", line)
        if x:
            ret[x.group("vpn")] = x.group("running") != "not"

    return ret

def vpn_enable(name):
    """Start a VPN."""
    run(settings.openvpn, "start", name)

def vpn_disable(name):
    """Stop a running VPN."""
    run(settings.openvpn, "stop", name)

def forward_drop():
    """Disable any and all forwarding unless explicitly said so."""
    run(settings.iptables, "-P", "FORWARD", "DROP")

def enable_nat(interface):
    """Enable NAT on this interface."""
    run(settings.iptables, "-t", "nat", "-A", "POSTROUTING",
        "-o", interface, "-j", "MASQUERADE")

def disable_nat(interface):
    """Disable NAT on this interface."""
    run(settings.iptables, "-t", "nat", "-D", "POSTROUTING",
        "-o", interface, "-j", "MASQUERADE")

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

handlers = {
    "nic_available": nic_available,
    "vpn_status": vpn_status,
    "vpn_enable": vpn_enable,
    "vpn_disable": vpn_disable,
    "forward_drop": forward_drop,
    "enable_nat": enable_nat,
    "disable_nat": disable_nat,
    "forward_enable": forward_enable,
    "forward_disable": forward_disable,
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("socket", nargs="?", default="/tmp/cuckoo-rooter", help="Unix socket path")
    parser.add_argument("-g", "--group", default="cuckoo", help="Unix socket group")
    parser.add_argument("--ifconfig", default="/sbin/ifconfig", help="Path to ifconfig")
    parser.add_argument("--openvpn", default="/etc/init.d/openvpn", help="Path to openvpn")
    parser.add_argument("--iptables", default="/sbin/iptables", help="Path to iptables")
    settings = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger("cuckoo-rooter")

    # Read configuration provided by Cuckoo.
    cuckoo = Config()
    vpn = Config("vpn")

    if not settings.openvpn or not os.path.exists(settings.openvpn):
        sys.exit("OpenVPN binary is not available, please configure!")

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
            output = e = None
            try:
                output = handlers[command](*args, **kwargs)
            except Exception as e:
                log.exception("Error executing command")

            server.sendto(json.dumps({
                "output": output,
                "exception": str(e) if e else None,
            }), addr)
