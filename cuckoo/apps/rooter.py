# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import os.path
import re
import socket
import stat
import subprocess
import sys

try:
    import grp
    HAVE_GRP = True
except ImportError:
    HAVE_GRP = False

_ifconfig = None
_service = None
_iptables = None
_ip = None

def run(*args):
    """Wrapper to Popen."""
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return stdout, stderr

def nic_available(interface):
    """Check if specified network interface is available."""
    try:
        subprocess.check_call([_ifconfig, interface],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False

def rt_available(rt_table):
    """Check if specified routing table is defined."""
    try:
        subprocess.check_call([_ip, "route", "list", "table", rt_table],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False

def vpn_status():
    """Gets current VPN status."""
    ret = {}
    for line in run(_service, "openvpn", "status")[0].split("\n"):
        x = re.search("'(?P<vpn>\\w+)'\\ is\\ (?P<running>not)?", line)
        if x:
            ret[x.group("vpn")] = x.group("running") != "not"

    return ret

def vpn_enable(name):
    """Start a VPN."""
    run(_service, "openvpn", "start", name)

def vpn_disable(name):
    """Stop a running VPN."""
    run(_service, "openvpn", "stop", name)

def forward_drop():
    """Disable any and all forwarding unless explicitly said so."""
    run(_iptables, "-P", "FORWARD", "DROP")

def enable_nat(interface):
    """Enable NAT on this interface."""
    run(_iptables, "-t", "nat", "-A", "POSTROUTING",
        "-o", interface, "-j", "MASQUERADE")

def disable_nat(interface):
    """Disable NAT on this interface."""
    while not run(_iptables, "-t", "nat", "-D", "POSTROUTING",
                  "-o", interface, "-j", "MASQUERADE")[1]:
        pass

def init_rttable(rt_table, interface):
    """Initialise routing table for this interface using routes
    from main table."""
    if rt_table in ["local", "main", "default"]:
        return

    stdout, _ = run(_ip, "route", "list", "dev", interface)
    for line in stdout.split("\n"):
        args = ["route", "add"] + [x for x in line.split(" ") if x]
        args += ["dev", interface, "table", rt_table]
        run(_ip, *args)

def flush_rttable(rt_table):
    """Flushes specified routing table entries."""
    if rt_table in ["local", "main", "default"]:
        return

    run(_ip, "route", "flush", "table", rt_table)

def local_dns_forward(ipaddr, dns_port, action):
    """Will route local dns to another port in the same interface, as in case of Tor"""
    run(_iptables, "-t", "nat", action, "PREROUTING", "-p", "tcp",
        "--dport", "53", "--source", ipaddr, "-j", "REDIRECT",
        "--to-ports", dns_port)

    run(_iptables, "-t", "nat", action, "PREROUTING", "-p", "udp",
        "--dport", "53", "--source", ipaddr, "-j", "REDIRECT", "--to-ports",
        dns_port)

def remote_dns_forward(ipaddr, remote_ip, action):
    """Will route dns to another host as in case of of Inetsim as vm"""
    run(_iptables, "-t", "nat", action, "PREROUTING", "-p",
        "tcp", "--dport", "53", "--source", ipaddr, "-j", "DNAT",
        "--to-destination", "%s:53" % remote_ip)

    run(_iptables, "-t", "nat", action, "PREROUTING", "-p",
        "udp", "--dport", "53", "--source", ipaddr, "-j", "DNAT",
        "--to-destination", "%s:53" % remote_ip)

def forward_enable(src, dst, ipaddr):
    """Enable forwarding a specific IP address from one interface into
    another."""
    run(_iptables, "-A", "FORWARD", "-i", src, "-o", dst,
        "--source", ipaddr, "-j", "ACCEPT")

    run(_iptables, "-A", "FORWARD", "-i", dst, "-o", src,
        "--destination", ipaddr, "-j", "ACCEPT")

def forward_disable(src, dst, ipaddr):
    """Disable forwarding of a specific IP address from one interface into
    another."""
    run(_iptables, "-D", "FORWARD", "-i", src, "-o", dst,
        "--source", ipaddr, "-j", "ACCEPT")

    run(_iptables, "-D", "FORWARD", "-i", dst, "-o", src,
        "--destination", ipaddr, "-j", "ACCEPT")

def srcroute_enable(rt_table, ipaddr):
    """Enable routing policy for specified source IP address."""
    run(_ip, "rule", "add", "from", ipaddr, "table", rt_table)
    run(_ip, "route", "flush", "cache")

def srcroute_disable(rt_table, ipaddr):
    """Disable routing policy for specified source IP address."""
    run(_ip, "rule", "del", "from", ipaddr, "table", rt_table)
    run(_ip, "route", "flush", "cache")

def inetsim_enable(ipaddr, inetsim_ip, resultserver_port, interface):
    """Enable hijacking of all traffic and send it to InetSIM."""
    run(_iptables, "-t", "nat", "-A", "PREROUTING", "--source", ipaddr,
        "-p", "tcp", "--syn", "!", "--dport", resultserver_port,
        "-j", "DNAT", "--to-destination", inetsim_ip)

    run(_iptables, "-A", "OUTPUT", "-m", "conntrack", "--ctstate",
        "INVALID", "-j", "DROP")

    run(_iptables, "-A", "OUTPUT", "-m", "state", "--state",
        "INVALID", "-j", "DROP")

    remote_dns_forward(ipaddr, inetsim_ip, "-A")

def inetsim_disable(ipaddr, inetsim_ip, resultserver_port):
    """Enable hijacking of all traffic and send it to InetSIM."""
    run(_iptables, "-D", "PREROUTING", "-t", "nat", "--source", ipaddr,
        "-p", "tcp", "--syn", "!", "--dport", resultserver_port, "-j", "DNAT",
        "--to-destination", inetsim_ip)

    run(_iptables, "-D", "OUTPUT", "-m", "conntrack", "--ctstate",
        "INVALID", "-j", "DROP")

    run(_iptables, "-D", "OUTPUT", "-m", "state", "--state",
        "INVALID", "-j", "DROP")

    remote_dns_forward(ipaddr, inetsim_ip, "-D")

def tor_enable(ipaddr, resultserver_port, dns_port, proxy_port):
    """Enable hijacking of all traffic and send it to TOR."""
    run(_iptables, "-t", "nat", "-A", "PREROUTING", "--source", ipaddr,
        "-p", "tcp", "--syn", "!", "--dport", resultserver_port,
        "-j", "REDIRECT", "--to-ports", proxy_port)

    run(_iptables, "-A", "OUTPUT", "-m", "conntrack", "--ctstate",
        "INVALID", "-j", "DROP")

    run(_iptables, "-A", "OUTPUT", "-m", "state", "--state",
        "INVALID", "-j", "DROP")

    local_dns_forward(ipaddr, dns_port, "-A")

def tor_disable(ipaddr, resultserver_port, dns_port, proxy_port):
    """Enable hijacking of all traffic and send it to TOR."""
    run(_iptables, "-t", "nat", "-D", "PREROUTING", "--source", ipaddr,
        "-p", "tcp", "--syn", "!", "--dport", resultserver_port,
        "-j", "REDIRECT", "--to-ports", proxy_port)

    run(_iptables, "-D", "OUTPUT", "-m", "conntrack", "--ctstate",
        "INVALID", "-j", "DROP")

    run(_iptables, "-D", "OUTPUT", "-m", "state", "--state",
        "INVALID", "-j", "DROP")

    local_dns_forward(ipaddr, dns_port, "-D")

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
    "inetsim_enable": inetsim_enable,
    "inetsim_disable": inetsim_disable,
    "tor_enable": tor_enable,
    "tor_disable": tor_disable,
}

def cuckoo_rooter(socket_path, group, ifconfig, service, iptables, ip):
    global _ifconfig, _service, _iptables, _ip

    log = logging.getLogger("cuckoo-rooter")

    if not HAVE_GRP:
        sys.exit(
            "Could not find the `grp` module, the Cuckoo Rooter is only "
            "supported under Linux operating systems."
        )

    if not service or not os.path.exists(service):
        sys.exit(
            "The service binary is not available, please configure it!\n"
            "Note that on CentOS you should provide --service /sbin/service, "
            "rather than using the Ubuntu/Debian default /usr/sbin/service."
        )

    if not ifconfig or not os.path.exists(ifconfig):
        sys.exit("The `ifconfig` binary is not available, eh?!")

    if not iptables or not os.path.exists(iptables):
        sys.exit("The `iptables` binary is not available, eh?!")

    if os.getuid():
        sys.exit("This utility is supposed to be ran as root user.")

    if os.path.exists(socket_path):
        os.remove(socket_path)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind(socket_path)

    # Provide the correct file ownership and permission so Cuckoo can use it
    # from an unprivileged process, based on Sean Whalen's routetor.
    try:
        gr = grp.getgrnam(group)
    except KeyError:
        sys.exit(
            "The group (`%s`) does not exist. Please define the group / user "
            "through which Cuckoo will connect to the rooter, e.g., "
            "./utils/rooter.py -g myuser" % group
        )

    os.chown(socket_path, 0, gr.gr_gid)
    os.chmod(socket_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IWGRP)

    # Initialize global variables.
    _ifconfig = ifconfig
    _service = service
    _iptables = iptables
    _ip = ip

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
            log.debug(
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
