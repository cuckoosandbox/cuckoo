# Copyright (C) 2014-2017 Cuckoo Foundation.
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

from cuckoo.misc import version as __version__

class s(object):
    ifconfig = None
    service = None
    iptables = None
    ip = None

log = logging.getLogger(__name__)

def run(*args):
    """Wrapper to Popen."""
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return stdout, stderr

def version():
    return {
        "version": __version__,
        "features": [],
    }

def nic_available(interface):
    """Check if specified network interface is available."""
    if not re.match("[a-zA-Z0-9-_]+$", interface):
        return False

    try:
        subprocess.check_call([s.ifconfig, interface],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False

def rt_available(rt_table):
    """Check if specified routing table is defined."""
    try:
        subprocess.check_call([s.ip, "route", "list", "table", rt_table],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False

def vpn_status():
    """Gets current VPN status."""
    ret = {}
    for line in run(s.service, "openvpn", "status")[0].split("\n"):
        x = re.search("'(?P<vpn>\\w+)'\\ is\\ (?P<running>not)?", line)
        if x:
            ret[x.group("vpn")] = x.group("running") != "not"

    return ret

def vpn_enable(name):
    """Start a VPN."""
    run(s.service, "openvpn", "start", name)

def vpn_disable(name):
    """Stop a running VPN."""
    run(s.service, "openvpn", "stop", name)

def forward_drop():
    """Disable any and all forwarding unless explicitly said so."""
    run(s.iptables, "-P", "FORWARD", "DROP")

def state_enable():
    """Enable stateful connection tracking."""
    run(
        s.iptables, "-A", "INPUT", "-m", "state",
        "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"
    )

def state_disable():
    """Disable stateful connection tracking."""
    while True:
        _, err = run(
            s.iptables, "-D", "INPUT", "-m", "state",
            "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"
        )
        if err:
            break

def enable_nat(interface):
    """Enable NAT on this interface."""
    run(s.iptables, "-t", "nat", "-A", "POSTROUTING",
        "-o", interface, "-j", "MASQUERADE")

def disable_nat(interface):
    """Disable NAT on this interface."""
    while True:
        _, err = run(
            s.iptables, "-t", "nat", "-D", "POSTROUTING",
            "-o", interface, "-j", "MASQUERADE"
        )
        if err:
            break

def init_rttable(rt_table, interface):
    """Initialise routing table for this interface using routes
    from main table."""
    if rt_table in ["local", "main", "default"]:
        return

    stdout, _ = run(s.ip, "route", "list", "dev", interface)
    for line in stdout.split("\n"):
        args = ["route", "add"] + [x for x in line.split(" ") if x]
        args += ["dev", interface, "table", rt_table]
        run(s.ip, *args)

def flush_rttable(rt_table):
    """Flushes specified routing table entries."""
    if rt_table in ["local", "main", "default"]:
        return

    run(s.ip, "route", "flush", "table", rt_table)

def local_dns_forward(ipaddr, dns_port, action):
    """Will route local dns to another port in the same interface, as in case of Tor"""
    run(s.iptables, "-t", "nat", action, "PREROUTING", "-p", "tcp",
        "--dport", "53", "--source", ipaddr, "-j", "REDIRECT",
        "--to-ports", dns_port)

    run(s.iptables, "-t", "nat", action, "PREROUTING", "-p", "udp",
        "--dport", "53", "--source", ipaddr, "-j", "REDIRECT", "--to-ports",
        dns_port)

def remote_dns_forward(action, vm_ip, dns_ip, dns_port):
    """Route DNS requests from the VM to a custom DNS on a separate network."""
    run(
        s.iptables, "-t", "nat", action, "PREROUTING", "-p", "tcp",
        "--dport", "53", "--source", vm_ip, "-j", "DNAT",
        "--to-destination", "%s:%s" % (dns_ip, dns_port)
    )

    run(
        s.iptables, "-t", "nat", action, "PREROUTING", "-p", "udp",
        "--dport", "53", "--source", vm_ip, "-j", "DNAT",
        "--to-destination", "%s:%s" % (dns_ip, dns_port)
    )

def forward_enable(src, dst, ipaddr):
    """Enable forwarding a specific IP address from one interface into
    another."""
    run(s.iptables, "-A", "FORWARD", "-i", src, "-o", dst,
        "--source", ipaddr, "-j", "ACCEPT")

    run(s.iptables, "-A", "FORWARD", "-i", dst, "-o", src,
        "--destination", ipaddr, "-j", "ACCEPT")

def forward_disable(src, dst, ipaddr):
    """Disable forwarding of a specific IP address from one interface into
    another."""
    run(s.iptables, "-D", "FORWARD", "-i", src, "-o", dst,
        "--source", ipaddr, "-j", "ACCEPT")

    run(s.iptables, "-D", "FORWARD", "-i", dst, "-o", src,
        "--destination", ipaddr, "-j", "ACCEPT")

def srcroute_enable(rt_table, ipaddr):
    """Enable routing policy for specified source IP address."""
    run(s.ip, "rule", "add", "from", ipaddr, "table", rt_table)
    run(s.ip, "route", "flush", "cache")

def srcroute_disable(rt_table, ipaddr):
    """Disable routing policy for specified source IP address."""
    run(s.ip, "rule", "del", "from", ipaddr, "table", rt_table)
    run(s.ip, "route", "flush", "cache")

def inetsim_enable(ipaddr, inetsim_ip, resultserver_port):
    """Enable hijacking of all traffic and send it to InetSIM."""
    run(s.iptables, "-t", "nat", "-A", "PREROUTING", "--source", ipaddr,
        "-p", "tcp", "--syn", "!", "--dport", resultserver_port,
        "-j", "DNAT", "--to-destination", inetsim_ip)

    run(s.iptables, "-A", "OUTPUT", "-m", "conntrack", "--ctstate",
        "INVALID", "-j", "DROP")

    run(s.iptables, "-A", "OUTPUT", "-m", "state", "--state",
        "INVALID", "-j", "DROP")

    remote_dns_forward(ipaddr, inetsim_ip, "-A")

def inetsim_disable(ipaddr, inetsim_ip, resultserver_port):
    """Enable hijacking of all traffic and send it to InetSIM."""
    run(s.iptables, "-D", "PREROUTING", "-t", "nat", "--source", ipaddr,
        "-p", "tcp", "--syn", "!", "--dport", resultserver_port, "-j", "DNAT",
        "--to-destination", inetsim_ip)

    run(s.iptables, "-D", "OUTPUT", "-m", "conntrack", "--ctstate",
        "INVALID", "-j", "DROP")

    run(s.iptables, "-D", "OUTPUT", "-m", "state", "--state",
        "INVALID", "-j", "DROP")

    remote_dns_forward(ipaddr, inetsim_ip, "-D")

def tor_toggle(action, vm_ip, resultserver_ip, dns_port, proxy_port):
    """Toggle Tor iptables routing rules."""
    remote_dns_forward(action, vm_ip, resultserver_ip, dns_port)

    run(
        s.iptables, "-t", "nat", action, "PREROUTING", "-p", "tcp",
        "--source", vm_ip, "!", "--destination", resultserver_ip,
        "-j", "DNAT", "--to-destination",
        "%s:%s" % (resultserver_ip, proxy_port)
    )

def tor_enable(vm_ip, resultserver_ip, dns_port, proxy_port):
    """Enable hijacking of all traffic and send it to TOR."""
    tor_toggle("-A", vm_ip, resultserver_ip, dns_port, proxy_port)

def tor_disable(vm_ip, resultserver_ip, dns_port, proxy_port):
    """Enable hijacking of all traffic and send it to TOR."""
    tor_toggle("-D", vm_ip, resultserver_ip, dns_port, proxy_port)

def drop_toggle(action, vm_ip, resultserver_ip, resultserver_port, agent_port):
    """Toggle iptables to allow internal Cuckoo traffic."""
    run(
        s.iptables, action, "INPUT", "--source", vm_ip, "-p", "tcp",
        "--destination", resultserver_ip, "--dport", "%s" % resultserver_port,
        "-j", "ACCEPT"
    )

    run(
        s.iptables, action, "OUTPUT", "--source", resultserver_ip,
        "-p", "tcp", "--destination", vm_ip, "--dport", "%s" % agent_port,
        "-j", "ACCEPT"
    )

    run(
        s.iptables, action, "INPUT", "--source", vm_ip, "-j", "DROP"
    )

def drop_enable(vm_ip, resultserver_ip, resultserver_port, agent_port=8000):
    """Enable complete dropping of all non-Cuckoo traffic by default."""
    return drop_toggle(
        "-A", vm_ip, resultserver_ip, resultserver_port, agent_port
    )

def drop_disable(vm_ip, resultserver_ip, resultserver_port, agent_port=8000):
    """Disable complete dropping of all non-Cuckoo traffic by default."""
    return drop_toggle(
        "-D", vm_ip, resultserver_ip, resultserver_port, agent_port
    )

handlers = {
    "version": version,
    "nic_available": nic_available,
    "rt_available": rt_available,
    "vpn_status": vpn_status,
    "vpn_enable": vpn_enable,
    "vpn_disable": vpn_disable,
    "forward_drop": forward_drop,
    "state_enable": state_enable,
    "state_disable": state_disable,
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
    "drop_enable": drop_enable,
    "drop_disable": drop_disable,
}

def cuckoo_rooter(socket_path, group, ifconfig, service, iptables, ip):
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

    if not ip or not os.path.exists(ip):
        sys.exit("The `ip` binary is not available, eh?!")

    if os.getuid():
        sys.exit(
            "This utility is supposed to be ran as root user. Please invoke "
            "it with the --sudo flag (e.g., 'cuckoo rooter --sudo') so it "
            "will automatically prompt for your password (this naturally only "
            "works for users with sudo capabilities)."
        )

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
            "The group ('%s') does not exist. Please define the group / user "
            "through which Cuckoo will connect to the rooter, e.g., "
            "'cuckoo rooter -g myuser'" % group
        )

    os.chown(socket_path, 0, gr.gr_gid)
    os.chmod(socket_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IWGRP)

    # Initialize global variables.
    s.ifconfig = ifconfig
    s.service = service
    s.iptables = iptables
    s.ip = ip

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
                log.exception("Error executing command: %s", e)

            server.sendto(json.dumps({
                "output": output,
                "exception": str(e) if e else None,
            }), addr)
