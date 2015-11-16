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
    log.info("Running: %s", args)
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return stdout, stderr

def nic_available(interface):
    try:
        subprocess.check_call([vpn.vpn.ifconfig, interface])
        return True
    except subprocess.CalledProcessError:
        return False

def vpn_status():
    ret = {}
    for line in run(vpn.vpn.service, "openvpn", "status")[0].split("\n"):
        x = re.search("'(?P<vpn>\\w+)'\\ is\\ (?P<running>not)?", line)
        if x:
            ret[x.group("vpn")] = x.group("running") != "not"

    return ret

def vpn_list():
    ret = []
    if not vpn.vpn.enabled:
        return ret

    for name in vpn.vpn.vpns.split(","):
        if not name.strip():
            continue

        if not hasattr(vpn, name):
            log.warning("Non-existing VPN defined: %r", name)
            continue

        entry = vpn.get(name)

        ret.append({
            "name": entry.name,
            "description": entry.description,
            "interface": entry.interface,
        })
    return ret

def vpn_enable(name):
    """Start a VPN."""
    run(vpn.vpn.service, "openvpn", "start", name)

def vpn_disable(name):
    """Stop a running VPN."""
    run(vpn.vpn.service, "openvpn", "stop", name)

def forward_drop():
    """Disable any and all forwarding unless explicitly said so."""
    run(vpn.vpn.iptables, "-P", "FORWARD", "DROP")

def enable_nat(interface):
    """Enable NAT on this interface."""
    run(vpn.vpn.iptables, "-t", "nat", "-A", "POSTROUTING",
        "-o", interface, "-j", "MASQUERADE")

def forward_enable(src, dst, ipaddr):
    """Enable forwarding a specific IP address from one interface into
    another."""
    run(vpn.vpn.iptables, "-A", "FORWARD", "-i", src, "-o", dst,
        "--source", ipaddr, "-j", "ACCEPT")

    run(vpn.vpn.iptables, "-A", "FORWARD", "-i", dst, "-o", src,
        "--destination", ipaddr, "-j", "ACCEPT")

def forward_disable(src, dst, ipaddr):
    """Disable forwarding of a specific IP address from one interface into
    another."""
    run(vpn.vpn.iptables, "-D", "FORWARD", "-i", src, "-o", dst,
        "--source", ipaddr, "-j", "ACCEPT")

    run(vpn.vpn.iptables, "-D", "FORWARD", "-i", dst, "-o", src,
        "--destination", ipaddr, "-j", "ACCEPT")

handlers = {
    "nic_available": nic_available,
    "vpn_status": vpn_status,
    "vpn_list": vpn_list,
    "vpn_enable": vpn_enable,
    "vpn_disable": vpn_disable,
    "forward_drop": forward_drop,
    "enable_nat": enable_nat,
    "forward_enable": forward_enable,
    "forward_disable": forward_disable,
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("socket", nargs="?", default="/tmp/cuckoo-rooter", help="Unix socket path")
    parser.add_argument("-g", "--group", default="cuckoo", help="Unix socket group")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger("cuckoo-rooter")

    # Read configuration provided by Cuckoo.
    cuckoo = Config()
    vpn = Config("vpn")

    if not vpn.vpn.openvpn or not os.path.isfile(vpn.vpn.openvpn):
        sys.exit("OpenVPN binary is not available, please configure!")

    if not vpn.vpn.ifconfig or not os.path.isfile(vpn.vpn.ifconfig):
        sys.exit("The `ifconfig` binary is not available, eh?!")

    if not vpn.vpn.service or not os.path.isfile(vpn.vpn.service):
        sys.exit("The `service` binary is not available, eh?!")

    if not vpn.vpn.iptables or not os.path.isfile(vpn.vpn.iptables):
        sys.exit("The `iptables` binary is not available, eh?!")

    if os.getuid():
        sys.exit("This utility is supposed to be ran as root.")

    if os.path.exists(args.socket):
        os.remove(args.socket)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind(args.socket)

    # Provide the correct file ownership and permission so Cuckoo can use it
    # from an unprivileged process, based on Sean Whalen's routetor.
    os.chown(args.socket, 0, grp.getgrnam(args.group).gr_gid)
    os.chmod(args.socket, stat.S_IRUSR | stat.S_IWUSR | stat.S_IWGRP)

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
