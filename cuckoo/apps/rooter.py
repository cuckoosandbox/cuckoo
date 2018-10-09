# Copyright (C) 2015-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import errno
import json
import logging
import os.path
import re
import socket
import stat
import subprocess
import sys

from cuckoo.common.colors import red
from cuckoo.misc import version as __version__

class s(object):
    service = None
    iptables = None
    ip = None

log = logging.getLogger(__name__)

def run(*args):
    """Wrapper to Popen."""
    log.debug("Running command: %s", " ".join(args))
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
    if not re.match("[a-zA-Z0-9-._]+$", interface):
        return False

    try:
        subprocess.check_call([s.ip, "link", "show", interface],
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

def dns_forward(action, vm_ip, dns_ip, dns_port="53"):
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
    run(
        s.iptables, "-A", "FORWARD", "-i", src, "-o", dst,
        "--source", ipaddr, "-j", "ACCEPT"
    )

    run(
        s.iptables, "-A", "FORWARD", "-i", dst, "-o", src,
        "--destination", ipaddr, "-j", "ACCEPT"
    )

def forward_disable(src, dst, ipaddr):
    """Disable forwarding of a specific IP address from one interface into
    another."""
    run(
        s.iptables, "-D", "FORWARD", "-i", src, "-o", dst,
        "--source", ipaddr, "-j", "ACCEPT"
    )

    run(
        s.iptables, "-D", "FORWARD", "-i", dst, "-o", src,
        "--destination", ipaddr, "-j", "ACCEPT"
    )

def srcroute_enable(rt_table, ipaddr):
    """Enable routing policy for specified source IP address."""
    run(s.ip, "rule", "add", "from", ipaddr, "table", rt_table)
    run(s.ip, "route", "flush", "cache")

def srcroute_disable(rt_table, ipaddr):
    """Disable routing policy for specified source IP address."""
    run(s.ip, "rule", "del", "from", ipaddr, "table", rt_table)
    run(s.ip, "route", "flush", "cache")

def inetsim_redirect_port(action, srcip, dstip, ports):
    """Note that the parameters (probably) mean the opposite of what they
    imply; this method adds or removes an iptables rule for redirect traffic
    from (srcip, srcport) to (dstip, dstport).
    E.g., if 192.168.56.101:80 -> 192.168.56.1:8080, then it redirects
    outgoing traffic from 192.168.56.101 to port 80 to 192.168.56.1:8080.
    """
    for entry in ports.split():
        if entry.count(":") != 1:
            log.debug("Invalid inetsim ports entry: %s", entry)
            continue
        srcport, dstport = entry.split(":")
        if not srcport.isdigit() or not dstport.isdigit():
            log.debug("Invalid inetsim ports entry: %s", entry)
            continue
        run(
            s.iptables, "-t", "nat", action, "PREROUTING", "--source", srcip,
            "-p", "tcp", "--syn", "--dport", srcport,
            "-j", "DNAT", "--to-destination", "%s:%s" % (dstip, dstport)
        )

def inetsim_enable(ipaddr, inetsim_ip, machinery_iface, resultserver_port,
                   ports):
    """Enable hijacking of all traffic and send it to InetSim."""
    inetsim_redirect_port("-A", ipaddr, inetsim_ip, ports)

    run(
        s.iptables, "-t", "nat", "-A", "PREROUTING", "--source", ipaddr,
        "-p", "tcp", "--syn", "!", "--dport", resultserver_port,
        "-j", "DNAT", "--to-destination", inetsim_ip
    )

    run(
        s.iptables, "-t", "nat", "-A", "PREROUTING", "--source", ipaddr,
        "-p", "udp", "-j", "DNAT", "--to-destination", inetsim_ip
    )

    run(
        s.iptables, "-A", "OUTPUT", "-m", "conntrack", "--ctstate",
        "INVALID", "-j", "DROP"
    )

    run(
        s.iptables, "-A", "OUTPUT", "-m", "state", "--state",
        "INVALID", "-j", "DROP"
    )

    dns_forward("-A", ipaddr, inetsim_ip)
    forward_enable(machinery_iface, machinery_iface, ipaddr)

    run(s.iptables, "-t", "nat", "-A", "POSTROUTING", "--source", ipaddr,
        "-o", machinery_iface, "--destination", inetsim_ip, "-j", "MASQUERADE")

    run(s.iptables, "-A", "OUTPUT", "-s", ipaddr, "-j", "DROP")

def inetsim_disable(ipaddr, inetsim_ip, machinery_iface, resultserver_port,
                    ports):
    """Enable hijacking of all traffic and send it to InetSim."""
    inetsim_redirect_port("-D", ipaddr, inetsim_ip, ports)

    run(
        s.iptables, "-D", "PREROUTING", "-t", "nat", "--source", ipaddr,
        "-p", "tcp", "--syn", "!", "--dport", resultserver_port, "-j", "DNAT",
        "--to-destination", inetsim_ip
    )
    run(
        s.iptables, "-t", "nat", "-D", "PREROUTING", "--source", ipaddr,
        "-p", "udp", "-j", "DNAT", "--to-destination", inetsim_ip
    )

    run(
        s.iptables, "-D", "OUTPUT", "-m", "conntrack", "--ctstate",
        "INVALID", "-j", "DROP"
    )

    run(
        s.iptables, "-D", "OUTPUT", "-m", "state", "--state",
        "INVALID", "-j", "DROP"
    )

    dns_forward("-D", ipaddr, inetsim_ip)
    forward_disable(machinery_iface, machinery_iface, ipaddr)

    run(s.iptables, "-t", "nat", "-D", "POSTROUTING", "--source", ipaddr,
        "-o", machinery_iface, "--destination", inetsim_ip, "-j", "MASQUERADE")

    run(s.iptables, "-D", "OUTPUT", "-s", ipaddr, "-j", "DROP")

def tor_toggle(action, vm_ip, resultserver_ip, dns_port, proxy_port):
    """Toggle Tor iptables routing rules."""
    dns_forward(action, vm_ip, resultserver_ip, dns_port)

    run(
        s.iptables, "-t", "nat", action, "PREROUTING", "-p", "tcp",
        "--source", vm_ip, "!", "--destination", resultserver_ip,
        "-j", "DNAT", "--to-destination",
        "%s:%s" % (resultserver_ip, proxy_port)
    )

    run(
        s.iptables, "-t", "nat", action, "PREROUTING", "-p", "udp",
        "--source", vm_ip, "!", "--destination", resultserver_ip,
        "-j", "DNAT", "--to-destination",
        "%s:%s" % (resultserver_ip, proxy_port)
    )
    run(s.iptables, action, "OUTPUT", "-s", vm_ip, "-j", "DROP")

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

    run(
        s.iptables, action, "OUTPUT", "--source", vm_ip, "-j", "DROP"
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

def cuckoo_rooter(socket_path, group, service, iptables, ip):
    try:
        import grp
    except ImportError:
        sys.exit(red(
            "Could not find the `grp` module, the Cuckoo Rooter is only "
            "supported under Linux operating systems."
        ))

    if not service or not os.path.exists(service):
        sys.exit(red(
            "The service binary is not available, please configure it!\n"
            "Note that on CentOS you should provide --service /sbin/service, "
            "rather than using the Ubuntu/Debian default /usr/sbin/service."
        ))

    if not iptables or not os.path.exists(iptables):
        sys.exit(red("The `iptables` binary is not available, eh?!"))

    if not ip or not os.path.exists(ip):
        sys.exit(red("The `ip` binary is not available, eh?!"))

    if os.getuid():
        sys.exit(red(
            "This utility is supposed to be ran as root user. Please invoke "
            "it with the --sudo flag (e.g., 'cuckoo rooter --sudo') so it "
            "will automatically prompt for your password (this naturally only "
            "works for users with sudo capabilities)."
        ))

    if os.path.exists(socket_path):
        os.remove(socket_path)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind(socket_path)

    # Provide the correct file ownership and permission so Cuckoo can use it
    # from an unprivileged process, based on Sean Whalen's routetor.
    try:
        gr = grp.getgrnam(group)
    except KeyError:
        sys.exit(red(
            "The group ('%s') does not exist. Please define the group / user "
            "through which Cuckoo will connect to the rooter, e.g., "
            "'cuckoo rooter -g myuser'." % group
        ))

    os.chown(socket_path, 0, gr.gr_gid)
    os.chmod(socket_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IWGRP)

    # Initialize global variables.
    s.service = service
    s.iptables = iptables
    s.ip = ip

    while True:
        try:
            command, addr = server.recvfrom(4096)
        except socket.error as e:
            if e.errno == errno.EINTR:
                continue
            raise e

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
            log.info(
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
