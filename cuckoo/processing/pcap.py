#!/usr/bin/python
# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2011  Claudio "nex" Guarnieri (nex@cuckoobox.org)
# http://www.cuckoobox.org
#
# This file is part of Cuckoo.
#
# Cuckoo is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Cuckoo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.

import os
import re
import sys
import socket

try:
    import dpkt
except ImportError:
    sys.exit(1)

class Pcap:
    def __init__(self, filepath):
        self.filepath = filepath
        self.tcp_connections = []
        self.udp_connections = []
        self.http_requests = []
        self.dns_requests = []
        self.dns_performed = []
        self.results = {}
        
    def check_http(self, tcpdata):
        try:
            dpkt.http.Request(tcpdata)
            return True
        except dpkt.dpkt.UnpackError:
            return False
        
    def add_http(self, tcpdata, dport):
        http = dpkt.http.Request(tcpdata)
        
        entry = {}
        entry["host"] = http.headers['host']
        entry["port"] = dport
        entry["data"] = tcpdata
        entry["uri"] = http.uri
        
        self.http_requests.append(entry)
        return True
    
    def check_dns(self, udpdata):
        try:
            dpkt.dns.DNS(udpdata)
            return True
        except:
            return False
    
    def add_dns(self, udpdata):
        dns = dpkt.dns.DNS(udpdata)
        name = dns.qd[0].name
        
        if name not in self.dns_performed:
            if re.search("in-addr.arpa", name):
                return False
            
            entry = {}
            entry["hostname"] = name

            try:
                ip = socket.gethostbyname(name)
            except socket.gaierror:
                ip = ""

            entry["ip"] = ip

            self.dns_requests.append(entry)
            self.dns_performed.append(name)
            
            return True
        return False
    
    def process(self):
        if not os.path.exists(self.filepath):
            return None

        if os.path.getsize(self.filepath) == 0:
            return None

        file = open(self.filepath, "rb")

        try:
            pcap = dpkt.pcap.Reader(file)
        except dpkt.dpkt.NeedData:
            return None
        
        try:
            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data

                    if ip.p == dpkt.ip.IP_PROTO_TCP:
                        tcp = ip.data

                        if len(tcp.data) > 0:
                            if self.check_http(tcp.data):
                                self.add_http(tcp.data, tcp.dport)

                            connection = {}
                            connection["src"] = socket.inet_ntoa(ip.src)
                            connection["dst"] = socket.inet_ntoa(ip.dst)
                            connection["sport"] = tcp.sport
                            connection["dport"] = tcp.dport

                            self.tcp_connections.append(connection)
                        else:
                            continue
                    elif ip.p == dpkt.ip.IP_PROTO_UDP:
                        udp = ip.data

                        if len(udp.data) > 0:
                            if udp.dport == 53:
                                if self.check_dns(udp.data):
                                    self.add_dns(udp.data)
                    #elif ip.p == dpkt.ip.IP_PROTO_ICMP:
                        #icmp = ip.data
                except AttributeError:
                    continue
        except dpkt.dpkt.NeedData:
            pass

        file.close()

        self.results["tcp"] = self.tcp_connections
        self.results["http"] = self.http_requests
        self.results["dns"] = self.dns_requests
        
        return self.results
