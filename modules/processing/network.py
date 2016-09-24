# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import hashlib
import logging
import json
import os
import re
import socket
import struct
import tempfile
import urlparse

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import LATEST_HTTPREPLAY, CUCKOO_ROOT
from lib.cuckoo.common.dns import resolve
from lib.cuckoo.common.irc import ircMessage
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import convert_to_printable, versiontuple
from lib.cuckoo.common.exceptions import CuckooProcessingError

try:
    import dpkt
    HAVE_DPKT = True
except ImportError:
    HAVE_DPKT = False

try:
    import httpreplay
    import httpreplay.cut

    # Be less verbose about httpreplay logging messages.
    logging.getLogger("httpreplay").setLevel(logging.CRITICAL)

    HAVE_HTTPREPLAY = True
except ImportError:
    HAVE_HTTPREPLAY = False

# Imports for the batch sort.
# http://stackoverflow.com/questions/10665925/how-to-sort-huge-files-with-python
# http://code.activestate.com/recipes/576755/
import heapq
from itertools import islice
from collections import namedtuple

Keyed = namedtuple("Keyed", ["key", "obj"])
Packet = namedtuple("Packet", ["raw", "ts"])

log = logging.getLogger(__name__)
cfg = Config()

# Urge users to upgrade to the latest version.
_v = getattr(httpreplay, "__version__", None) if HAVE_HTTPREPLAY else None
if _v and versiontuple(_v) < versiontuple(LATEST_HTTPREPLAY):
    log.warning(
        "You are using version %s of HTTPReplay, rather than the latest "
        "version %s, which may not handle various corner cases and/or TLS "
        "cipher suites correctly. This could result in not getting all the "
        "HTTP/HTTPS streams that are available or corrupt some streams that "
        "were not handled correctly before. Please upgrade it to the latest "
        "version (`pip install --upgrade httpreplay`).",
        _v, LATEST_HTTPREPLAY,
    )

class Pcap(object):
    """Reads network data from PCAP file."""
    ssl_ports = 443,

    notified_dpkt = False

    def __init__(self, filepath, options):
        """Creates a new instance.
        @param filepath: path to PCAP file
        @param options: config options
        """
        self.filepath = filepath
        self.options = options

        # List of all hosts.
        self.hosts = []
        # List containing all non-private IP addresses.
        self.unique_hosts = []
        # List of unique domains.
        self.unique_domains = []
        # List containing all TCP packets.
        self.tcp_connections = []
        self.tcp_connections_seen = set()
        # Lookup table to identify connection requests to services or IP
        # addresses that are no longer available.
        self.tcp_connections_dead = {}
        self.dead_hosts = {}
        self.alive_hosts = {}
        # List containing all UDP packets.
        self.udp_connections = []
        self.udp_connections_seen = set()
        # List containing all ICMP requests.
        self.icmp_requests = []
        # List containing all HTTP requests.
        self.http_requests = {}
        # List containing all TLS/SSL3 key combinations.
        self.tls_keys = []
        # List containing all DNS requests.
        self.dns_requests = {}
        self.dns_answers = set()
        # List containing all SMTP requests.
        self.smtp_requests = []
        # Reconstructed SMTP flow.
        self.smtp_flow = {}
        # List containing all IRC requests.
        self.irc_requests = []
        # Dictionary containing all the results of this processing.
        self.results = {}
        # List containing all whitelist entries.
        self.whitelist = self._build_whitelist()
        # List for holding whitelisted IP-s according to DNS responses
        self.whitelist_ips = []
        # state of whitelisting
        self.whitelist_enabled = self._build_whitelist_conf()
        # List of known good DNS servers
        self.known_dns = self._build_known_dns()

    def _build_whitelist(self):
        result = []
        whitelist_path = os.path.join(
            CUCKOO_ROOT, "data", "whitelist", "domain.txt"
        )
        for line in open(whitelist_path, 'rb'):
            result.append(line.strip())
        return result

    def _build_whitelist_conf(self):
        """Check if whitelisting is enabled."""
        if not self.options.get("whitelist-dns"):
            log.debug("Whitelisting Disabled.")
            return False

        return True

    def _is_whitelisted(self, conn, hostname):
        """Checks if whitelisting conditions are met"""
        # is whitelistng enabled ?
        if not self.whitelist_enabled:
            return False
        
        # is DNS recording coming from allowed NS server
        if not self.known_dns:
            pass
        elif (conn.get("src") in self.known_dns or 
              conn.get("dst") in self.known_dns):
            pass
        else:
            return False

        # is hostname whitelisted
        if hostname not in self.whitelist:
            return False
        
        return True

    def _build_known_dns(self):
        """Build known DNS list."""
        result = []
        _known_dns = self.options.get("allowed-dns")
        if _known_dns is not None:
            for r in _known_dns.split(","):
                result.append(r.strip())
            return result

        return []

    def _dns_gethostbyname(self, name):
        """Get host by name wrapper.
        @param name: hostname.
        @return: IP address or blank
        """
        if cfg.processing.resolve_dns:
            ip = resolve(name)
        else:
            ip = ""
        return ip

    def _is_private_ip(self, ip):
        """Check if the IP belongs to private network blocks.
        @param ip: IP address to verify.
        @return: boolean representing whether the IP belongs or not to
                 a private network block.
        """
        networks = [
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.88.99.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "240.0.0.0/4",
            "255.255.255.255/32",
            "224.0.0.0/4"
        ]

        for network in networks:
            try:
                ipaddr = struct.unpack(">I", socket.inet_aton(ip))[0]

                netaddr, bits = network.split("/")

                network_low = struct.unpack(">I", socket.inet_aton(netaddr))[0]
                network_high = network_low | (1 << (32 - int(bits))) - 1

                if ipaddr <= network_high and ipaddr >= network_low:
                    return True
            except:
                continue

        return False

    def _add_hosts(self, connection):
        """Add IPs to unique list.
        @param connection: connection data
        """
        try:
            # TODO: Perhaps this block should be removed.
            # If there is a packet from a non-local IP address, which hasn't
            # been seen before, it means that the connection wasn't initiated
            # during the time of the current analysis.
            if connection["src"] not in self.hosts:
                ip = convert_to_printable(connection["src"])

                # We consider the IP only if it hasn't been seen before.
                if ip not in self.hosts:
                    # If the IP is not a local one, this might be a leftover
                    # packet as described in issue #249.
                    if self._is_private_ip(ip):
                        self.hosts.append(ip)

            if connection["dst"] not in self.hosts:
                ip = convert_to_printable(connection["dst"])

                if ip not in self.hosts:
                    self.hosts.append(ip)

                    # We add external IPs to the list, only the first time
                    # we see them and if they're the destination of the
                    # first packet they appear in.
                    if not self._is_private_ip(ip) and ip not in self.whitelist_ips:
                        self.unique_hosts.append(ip)
        except:
            pass

    def _tcp_dissect(self, conn, data):
        """Runs all TCP dissectors.
        @param conn: connection.
        @param data: payload data.
        """
        if self._check_http(data):
            self._add_http(data, conn["dport"])

        # SMTP.
        if conn["dport"] == 25:
            self._reassemble_smtp(conn, data)

        # IRC.
        if conn["dport"] != 21 and self._check_irc(data):
            self._add_irc(data)

        # HTTPS.
        if conn["dport"] in self.ssl_ports or conn["sport"] in self.ssl_ports:
            self._https_identify(conn, data)

    def _udp_dissect(self, conn, data):
        """Runs all UDP dissectors.
        @param conn: connection.
        @param data: payload data.
        """
        # Select DNS and MDNS traffic.
        if conn["dport"] == 53 or conn["sport"] == 53 or conn["dport"] == 5353 or conn["sport"] == 5353:
            if self._check_dns(data):
                self._add_dns(conn, data)

    def _check_icmp(self, icmp_data):
        """Checks for ICMP traffic.
        @param icmp_data: ICMP data flow.
        """
        try:
            return isinstance(icmp_data, dpkt.icmp.ICMP) and \
                len(icmp_data.data) > 0
        except:
            return False

    def _icmp_dissect(self, conn, data):
        """Runs all ICMP dissectors.
        @param conn: connection.
        @param data: payload data.
        """

        if self._check_icmp(data):
            # If ICMP packets are coming from the host, it probably isn't
            # relevant traffic, hence we can skip from reporting it.
            if conn["src"] == cfg.resultserver.ip:
                return

            entry = {}
            entry["src"] = conn["src"]
            entry["dst"] = conn["dst"]
            entry["type"] = data.type

            # Extract data from dpkg.icmp.ICMP.
            try:
                entry["data"] = convert_to_printable(data.data.data)
            except:
                entry["data"] = ""

            self.icmp_requests.append(entry)

    def _check_dns(self, udpdata):
        """Checks for DNS traffic.
        @param udpdata: UDP data flow.
        """
        try:
            dpkt.dns.DNS(udpdata)
        except:
            return False

        return True

    def _add_dns(self, conn, udpdata):
        """Adds a DNS data flow.
        @param udpdata: UDP data flow.
        """
        dns = dpkt.dns.DNS(udpdata)

        # DNS query parsing.
        query = {}
        # Temporary list for found A or AAAA responses.
        _ip = []

        if dns.rcode == dpkt.dns.DNS_RCODE_NOERR or \
                dns.qr == dpkt.dns.DNS_R or \
                dns.opcode == dpkt.dns.DNS_QUERY or True:
            # DNS question.
            try:
                q_name = dns.qd[0].name
                q_type = dns.qd[0].type
            except IndexError:
                return False

            # DNS RR type mapping.
            # See: http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
            # See: https://github.com/kbandla/dpkt/blob/master/dpkt/dns.py#L42
            query["request"] = q_name
            if q_type == dpkt.dns.DNS_A:
                query["type"] = "A"
            elif q_type == dpkt.dns.DNS_AAAA:
                query["type"] = "AAAA"
            elif q_type == dpkt.dns.DNS_CNAME:
                query["type"] = "CNAME"
            elif q_type == dpkt.dns.DNS_MX:
                query["type"] = "MX"
            elif q_type == dpkt.dns.DNS_PTR:
                query["type"] = "PTR"
            elif q_type == dpkt.dns.DNS_NS:
                query["type"] = "NS"
            elif q_type == dpkt.dns.DNS_SOA:
                query["type"] = "SOA"
            elif q_type == dpkt.dns.DNS_HINFO:
                query["type"] = "HINFO"
            elif q_type == dpkt.dns.DNS_TXT:
                query["type"] = "TXT"
            elif q_type == dpkt.dns.DNS_SRV:
                query["type"] = "SRV"
            elif q_type == dpkt.dns.DNS_ANY:
                # For example MDNS requests have q_type=255.
                query["type"] = "All"
            else:
                # Some requests are not parsed by dpkt.
                query["type"] = "None"

            # DNS answer.
            query["answers"] = []
            for answer in dns.an:
                ans = {}
                if answer.type == dpkt.dns.DNS_A:
                    ans["type"] = "A"
                    try:
                        ans["data"] = socket.inet_ntoa(answer.rdata)
                        _ip.append(ans["data"])
                    except socket.error:
                        continue
                elif answer.type == dpkt.dns.DNS_AAAA:
                    ans["type"] = "AAAA"
                    try:
                        ans["data"] = socket.inet_ntop(socket.AF_INET6,
                                                       answer.rdata)
                        _ip.append(ans["data"])
                    except (socket.error, ValueError):
                        continue
                elif answer.type == dpkt.dns.DNS_CNAME:
                    ans["type"] = "CNAME"
                    ans["data"] = answer.cname
                elif answer.type == dpkt.dns.DNS_MX:
                    ans["type"] = "MX"
                    ans["data"] = answer.mxname
                elif answer.type == dpkt.dns.DNS_PTR:
                    ans["type"] = "PTR"
                    ans["data"] = answer.ptrname
                elif answer.type == dpkt.dns.DNS_NS:
                    ans["type"] = "NS"
                    ans["data"] = answer.nsname
                elif answer.type == dpkt.dns.DNS_SOA:
                    ans["type"] = "SOA"
                    ans["data"] = ",".join([answer.mname,
                                           answer.rname,
                                           str(answer.serial),
                                           str(answer.refresh),
                                           str(answer.retry),
                                           str(answer.expire),
                                           str(answer.minimum)])
                elif answer.type == dpkt.dns.DNS_HINFO:
                    ans["type"] = "HINFO"
                    ans["data"] = " ".join(answer.text)
                elif answer.type == dpkt.dns.DNS_TXT:
                    ans["type"] = "TXT"
                    ans["data"] = " ".join(answer.text)

                # TODO: add srv handling
                query["answers"].append(ans)

            if self._is_whitelisted(conn, q_name):
                log.debug("DNS target {0} whitelisted. Skipping ...".format(q_name))
                self.whitelist_ips = self.whitelist_ips + _ip
                return True

            self._add_domain(query["request"])

            reqtuple = query["type"], query["request"]
            if reqtuple not in self.dns_requests:
                self.dns_requests[reqtuple] = query
            else:
                new_answers = set((i["type"], i["data"]) for i in query["answers"]) - self.dns_answers
                self.dns_requests[reqtuple]["answers"] += [dict(type=i[0], data=i[1]) for i in new_answers]

        return True

    def _add_domain(self, domain):
        """Add a domain to unique list.
        @param domain: domain name.
        """
        filters = [
            ".*\\.windows\\.com$",
            ".*\\.in\\-addr\\.arpa$"
        ]

        regexps = [re.compile(filter) for filter in filters]
        for regexp in regexps:
            if regexp.match(domain):
                return

        for entry in self.unique_domains:
            if entry["domain"] == domain:
                return

        self.unique_domains.append({"domain": domain,
                                    "ip": self._dns_gethostbyname(domain)})

    def _check_http(self, tcpdata):
        """Checks for HTTP traffic.
        @param tcpdata: TCP data flow.
        """
        try:
            r = dpkt.http.Request()
            r.method, r.version, r.uri = None, None, None
            r.unpack(tcpdata)
        except dpkt.dpkt.UnpackError:
            if r.method is not None or r.version is not None or \
                    r.uri is not None:
                return True
            return False

        return True

    def _add_http(self, tcpdata, dport):
        """Adds an HTTP flow.
        @param tcpdata: TCP data flow.
        @param dport: destination port.
        """
        if tcpdata in self.http_requests:
            self.http_requests[tcpdata]["count"] += 1
            return True

        try:
            http = dpkt.http.Request()
            http.unpack(tcpdata)
        except dpkt.dpkt.UnpackError:
            pass

        try:
            entry = {"count": 1}

            if "host" in http.headers:
                entry["host"] = convert_to_printable(http.headers["host"])
            else:
                entry["host"] = ""

            entry["port"] = dport

            # Manually deal with cases when destination port is not the
            # default one and it is not included in host header.
            netloc = entry["host"]
            if dport != 80 and ":" not in netloc:
                netloc += ":" + str(entry["port"])

            entry["data"] = convert_to_printable(tcpdata)
            url = urlparse.urlunparse(("http", netloc, http.uri,
                                       None, None, None))
            entry["uri"] = convert_to_printable(url)
            entry["body"] = convert_to_printable(http.body)
            entry["path"] = convert_to_printable(http.uri)

            if "user-agent" in http.headers:
                entry["user-agent"] = \
                    convert_to_printable(http.headers["user-agent"])

            entry["version"] = convert_to_printable(http.version)
            entry["method"] = convert_to_printable(http.method)

            self.http_requests[tcpdata] = entry
        except Exception:
            return False

        return True

    def _https_identify(self, conn, data):
        """Extract a combination of the Session ID, Client Random, and Server
        Random in order to identify the accompanying master secret later."""
        if not hasattr(dpkt.ssl, "TLSRecord"):
            if not Pcap.notified_dpkt:
                Pcap.notified_dpkt = True
                log.warning("Using an old version of dpkt that does not "
                            "support TLS streams (install the latest with "
                            "`pip install dpkt`)")
            return

        try:
            record = dpkt.ssl.TLSRecord(data)
        except dpkt.NeedData:
            return
        except:
            log.exception("Error reading possible TLS Record")
            return

        # Is this a valid TLS packet?
        if record.type not in dpkt.ssl.RECORD_TYPES:
            return

        try:
            record = dpkt.ssl.RECORD_TYPES[record.type](record.data)
        except dpkt.ssl.SSL3Exception:
            return
        except dpkt.NeedData:
            log.exception("Incomplete possible TLS Handshake record found")
            return

        # Is this a TLSv1 Handshake packet?
        if not isinstance(record, dpkt.ssl.TLSHandshake):
            return

        # We're only interested in the TLS Server Hello packets.
        if not isinstance(record.data, dpkt.ssl.TLSServerHello):
            return

        # Extract the server random and the session id.
        self.tls_keys.append({
            "server_random": record.data.random.encode("hex"),
            "session_id": record.data.session_id.encode("hex"),
        })

    def _reassemble_smtp(self, conn, data):
        """Reassemble a SMTP flow.
        @param conn: connection dict.
        @param data: raw data.
        """
        if conn["dst"] in self.smtp_flow:
            self.smtp_flow[conn["dst"]] += data
        else:
            self.smtp_flow[conn["dst"]] = data

    def _process_smtp(self):
        """Process SMTP flow."""
        for conn, data in self.smtp_flow.iteritems():
            # Detect new SMTP flow.
            if data.startswith(("EHLO", "HELO")):
                self.smtp_requests.append({"dst": conn, "raw": data})

    def _check_irc(self, tcpdata):
        """
        Checks for IRC traffic.
        @param tcpdata: tcp data flow
        """
        try:
            req = ircMessage()
        except Exception:
            return False

        return req.isthereIRC(tcpdata)

    def _add_irc(self, tcpdata):
        """
        Adds an IRC communication.
        @param tcpdata: TCP data in flow
        @param dport: destination port
        """

        try:
            reqc = ircMessage()
            reqs = ircMessage()
            filters_sc = ["266"]
            self.irc_requests = self.irc_requests + \
                reqc.getClientMessages(tcpdata) + \
                reqs.getServerMessagesFilter(tcpdata, filters_sc)
        except Exception:
            return False

        return True

    def run(self):
        """Process PCAP.
        @return: dict with network analysis data.
        """

        try:
            file = open(self.filepath, "rb")
        except (IOError, OSError):
            log.error("Unable to open %s" % self.filepath)
            return self.results

        try:
            pcap = dpkt.pcap.Reader(file)
        except dpkt.dpkt.NeedData:
            log.error("Unable to read PCAP file at path \"%s\".",
                      self.filepath)
            return self.results
        except ValueError:
            log.error("Unable to read PCAP file at path \"%s\". File is "
                      "corrupted or wrong format." % self.filepath)
            return self.results

        offset = file.tell()
        first_ts = None
        for ts, buf in pcap:
            if not first_ts:
                first_ts = ts

            try:
                ip = iplayer_from_raw(buf, pcap.datalink())

                connection = {}
                if isinstance(ip, dpkt.ip.IP):
                    connection["src"] = socket.inet_ntoa(ip.src)
                    connection["dst"] = socket.inet_ntoa(ip.dst)
                elif isinstance(ip, dpkt.ip6.IP6):
                    connection["src"] = socket.inet_ntop(socket.AF_INET6,
                                                         ip.src)
                    connection["dst"] = socket.inet_ntop(socket.AF_INET6,
                                                         ip.dst)
                else:
                    offset = file.tell()
                    continue

                self._add_hosts(connection)

                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    tcp = ip.data
                    if not isinstance(tcp, dpkt.tcp.TCP):
                        tcp = dpkt.tcp.TCP(tcp)

                    if tcp.data:
                        connection["sport"] = tcp.sport
                        connection["dport"] = tcp.dport
                        self._tcp_dissect(connection, tcp.data)

                        src, sport, dst, dport = (connection["src"], connection["sport"], connection["dst"], connection["dport"])
                        if not ((dst, dport, src, sport) in self.tcp_connections_seen or (src, sport, dst, dport) in self.tcp_connections_seen):
                            self.tcp_connections.append((src, sport, dst, dport, offset, ts-first_ts))
                            self.tcp_connections_seen.add((src, sport, dst, dport))

                        self.alive_hosts[dst, dport] = True
                    else:
                        ipconn = (
                            connection["src"], tcp.sport,
                            connection["dst"], tcp.dport,
                        )
                        seqack = self.tcp_connections_dead.get(ipconn)
                        if seqack == (tcp.seq, tcp.ack):
                            host = connection["dst"], tcp.dport
                            self.dead_hosts[host] = self.dead_hosts.get(host, 1) + 1

                        self.tcp_connections_dead[ipconn] = tcp.seq, tcp.ack

                elif ip.p == dpkt.ip.IP_PROTO_UDP:
                    udp = ip.data
                    if not isinstance(udp, dpkt.udp.UDP):
                        udp = dpkt.udp.UDP(udp)

                    if len(udp.data) > 0:
                        connection["sport"] = udp.sport
                        connection["dport"] = udp.dport
                        self._udp_dissect(connection, udp.data)

                        src, sport, dst, dport = (connection["src"], connection["sport"], connection["dst"], connection["dport"])
                        if not ((dst, dport, src, sport) in self.udp_connections_seen or (src, sport, dst, dport) in self.udp_connections_seen):
                            self.udp_connections.append((src, sport, dst, dport, offset, ts-first_ts))
                            self.udp_connections_seen.add((src, sport, dst, dport))

                elif ip.p == dpkt.ip.IP_PROTO_ICMP:
                    icmp = ip.data
                    if not isinstance(icmp, dpkt.icmp.ICMP):
                        icmp = dpkt.icmp.ICMP(icmp)

                    self._icmp_dissect(connection, icmp)

                offset = file.tell()
            except AttributeError:
                continue
            except dpkt.dpkt.NeedData:
                continue
            except Exception as e:
                log.exception("Failed to process packet: %s", e)

        file.close()

        # Post processors for reconstructed flows.
        self._process_smtp()

        # Build results dict.
        self.results["hosts"] = self.unique_hosts
        self.results["domains"] = self.unique_domains
        self.results["tcp"] = [conn_from_flowtuple(i) for i in self.tcp_connections]
        self.results["udp"] = [conn_from_flowtuple(i) for i in self.udp_connections]
        self.results["icmp"] = self.icmp_requests
        self.results["http"] = self.http_requests.values()
        self.results["tls"] = self.tls_keys
        self.results["dns"] = self.dns_requests.values()
        self.results["smtp"] = self.smtp_requests
        self.results["irc"] = self.irc_requests

        self.results["dead_hosts"] = []

        # Report each IP/port combination as a dead host if we've had to retry
        # at least 3 times to connect to it and if no successful connections
        # were detected throughout the analysis.
        for (ip, port), count in self.dead_hosts.items():
            if count < 3 or (ip, port) in self.alive_hosts:
                continue

            # Report once.
            if (ip, port) not in self.results["dead_hosts"]:
                self.results["dead_hosts"].append((ip, port))

        return self.results

class Pcap2(object):
    """Interprets the PCAP file through the httpreplay library which parses
    the various protocols, decrypts and decodes them, and then provides us
    with the high level representation of it."""

    def __init__(self, pcap_path, tlsmaster, network_path):
        self.pcap_path = pcap_path
        self.network_path = network_path

        self.handlers = {
            25: httpreplay.cut.smtp_handler,
            80: httpreplay.cut.http_handler,
            8000: httpreplay.cut.http_handler,
            8080: httpreplay.cut.http_handler,
            443: lambda: httpreplay.cut.https_handler(tlsmaster),
            4443: lambda: httpreplay.cut.https_handler(tlsmaster),
        }

    def run(self):
        results = {
            "http_ex": [],
            "https_ex": [],
        }

        if not os.path.exists(self.network_path):
            os.mkdir(self.network_path)

        r = httpreplay.reader.PcapReader(open(self.pcap_path, "rb"))
        r.tcp = httpreplay.smegma.TCPPacketStreamer(r, self.handlers)

        l = sorted(r.process(), key=lambda x: x[1])
        for s, ts, protocol, sent, recv in l:
            srcip, srcport, dstip, dstport = s

            if protocol == "http" or protocol == "https":
                request = sent.raw.split("\r\n\r\n", 1)[0]
                response = recv.raw.split("\r\n\r\n", 1)[0]

                md5 = hashlib.md5(recv.body or "").hexdigest()
                sha1 = hashlib.sha1(recv.body or "").hexdigest()

                filepath = os.path.join(self.network_path, sha1)
                open(filepath, "wb").write(recv.body or "")

                results["%s_ex" % protocol].append({
                    "src": srcip, "sport": srcport,
                    "dst": dstip, "dport": dstport,
                    "protocol": protocol,
                    "method": sent.method,
                    "host": sent.headers.get("host", dstip),
                    "uri": sent.uri,
                    "request": request.decode("latin-1"),
                    "response": response.decode("latin-1"),
                    "md5": md5,
                    "sha1": sha1,
                    "path": filepath,
                })

        return results

class NetworkAnalysis(Processing):
    """Network analysis."""

    order = 2
    key = "network"

    def run(self):
        results = {}

        # Include any results provided by the mitm script.
        results["mitm"] = []
        if os.path.exists(self.mitmout_path):
            for line in open(self.mitmout_path, "rb"):
                try:
                    results["mitm"].append(json.loads(line))
                except:
                    results["mitm"].append(line)

        if not os.path.exists(self.pcap_path):
            log.warning("The PCAP file does not exist at path \"%s\".",
                        self.pcap_path)
            return results

        if os.path.getsize(self.pcap_path) == 0:
            log.error("The PCAP file at path \"%s\" is empty." % self.pcap_path)
            return results

        # PCAP file hash.
        if os.path.exists(self.pcap_path):
            results["pcap_sha256"] = File(self.pcap_path).get_sha256()

        if not HAVE_DPKT and not HAVE_HTTPREPLAY:
            log.error("Both Python HTTPReplay and Python DPKT are not "
                      "installed, no PCAP analysis possible.")
            return results

        sorted_path = self.pcap_path.replace("dump.", "dump_sorted.")
        if cfg.processing.sort_pcap:
            sort_pcap(self.pcap_path, sorted_path)
            pcap_path = sorted_path

            # Sorted PCAP file hash.
            if os.path.exists(sorted_path):
                results["sorted_pcap_sha256"] = File(sorted_path).get_sha256()
        else:
            pcap_path = self.pcap_path

        if HAVE_DPKT:
            results.update(Pcap(pcap_path, self.options).run())

        if HAVE_HTTPREPLAY and os.path.exists(pcap_path):
            try:
                p2 = Pcap2(pcap_path, self.get_tlsmaster(), self.network_path)
                results.update(p2.run())
            except:
                log.exception("Error running httpreplay-based PCAP analysis")

        return results

    def get_tlsmaster(self):
        """Obtain the client/server random to TLS master secrets mapping that
        we have obtained through dynamic analysis."""
        tlsmaster = {}
        summary = self.results.get("behavior", {}).get("summary", {})
        for entry in summary.get("tls_master", []):
            client_random, server_random, master_secret = entry
            client_random = client_random.decode("hex")
            server_random = server_random.decode("hex")
            master_secret = master_secret.decode("hex")
            tlsmaster[client_random, server_random] = master_secret
        return tlsmaster

def iplayer_from_raw(raw, linktype=1):
    """Converts a raw packet to a dpkt packet regarding of link type.
    @param raw: raw packet
    @param linktype: integer describing link type as expected by dpkt
    """
    if linktype == 1:  # ethernet
        try:
            pkt = dpkt.ethernet.Ethernet(raw)
            return pkt.data
        except dpkt.NeedData:
            pass
    elif linktype == 101:  # raw
        return dpkt.ip.IP(raw)
    else:
        raise CuckooProcessingError("unknown PCAP linktype")

def conn_from_flowtuple(ft):
    """Convert the flow tuple into a dictionary (suitable for JSON)"""
    sip, sport, dip, dport, offset, relts = ft
    return {"src": sip, "sport": sport,
            "dst": dip, "dport": dport,
            "offset": offset, "time": relts}

# input_iterator should be a class that also supports writing so we can use
# it for the temp files
# this code is mostly taken from some SO post, can't remember the url though
def batch_sort(input_iterator, output_path, buffer_size=32000, output_class=None):
    """batch sort helper with temporary files, supports sorting large stuff"""
    if not output_class:
        output_class = input_iterator.__class__

    chunks = []
    try:
        while True:
            current_chunk = list(islice(input_iterator, buffer_size))
            if not current_chunk:
                break

            current_chunk.sort()
            fd, filepath = tempfile.mkstemp()
            os.close(fd)
            output_chunk = output_class(filepath)
            chunks.append(output_chunk)

            for elem in current_chunk:
                output_chunk.write(elem.obj)
            output_chunk.close()

        output_file = output_class(output_path)
        for elem in heapq.merge(*chunks):
            output_file.write(elem.obj)
        output_file.close()
    finally:
        for chunk in chunks:
            try:
                chunk.close()
                os.remove(chunk.name)
            except Exception:
                pass

class SortCap(object):
    """SortCap is a wrapper around the packet lib (dpkt) that allows us to sort pcaps
    together with the batch_sort function above."""

    def __init__(self, path, linktype=1):
        self.name = path
        self.linktype = linktype
        self.fd = None
        self.ctr = 0  # counter to pass through packets without flow info (non-IP)
        self.conns = set()

    def write(self, p):
        if not self.fd:
            self.fd = dpkt.pcap.Writer(open(self.name, "wb"), linktype=self.linktype)
        self.fd.writepkt(p.raw, p.ts)

    def __iter__(self):
        if not self.fd:
            self.fd = dpkt.pcap.Reader(open(self.name, "rb"))
            self.fditer = iter(self.fd)
            self.linktype = self.fd.datalink()
        return self

    def close(self):
        if self.fd:
            self.fd.close()
            self.fd = None

    def next(self):
        rp = next(self.fditer)
        if rp is None:
            return None

        self.ctr += 1

        ts, raw = rp
        rpkt = Packet(raw, ts)

        sip, dip, sport, dport, proto = flowtuple_from_raw(raw, self.linktype)

        # check other direction of same flow
        if (dip, sip, dport, sport, proto) in self.conns:
            flowtuple = (dip, sip, dport, sport, proto)
        else:
            flowtuple = (sip, dip, sport, dport, proto)

        self.conns.add(flowtuple)
        return Keyed((flowtuple, ts, self.ctr), rpkt)

def sort_pcap(inpath, outpath):
    """Use SortCap class together with batch_sort to sort a pcap"""
    inc = SortCap(inpath)
    batch_sort(inc, outpath, output_class=lambda path: SortCap(path, linktype=inc.linktype))
    return 0

def flowtuple_from_raw(raw, linktype=1):
    """Parse a packet from a pcap just enough to gain a flow description tuple"""
    ip = iplayer_from_raw(raw, linktype)

    if isinstance(ip, dpkt.ip.IP):
        sip, dip = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
        proto = ip.p

        if proto == dpkt.ip.IP_PROTO_TCP or proto == dpkt.ip.IP_PROTO_UDP:
            l3 = ip.data
            sport, dport = l3.sport, l3.dport
        else:
            sport, dport = 0, 0

    else:
        sip, dip, proto = 0, 0, -1
        sport, dport = 0, 0

    flowtuple = (sip, dip, sport, dport, proto)
    return flowtuple

def payload_from_raw(raw, linktype=1):
    """Get the payload from a packet, the data below TCP/UDP basically"""
    ip = iplayer_from_raw(raw, linktype)
    try:
        return ip.data.data
    except:
        return ""

def next_connection_packets(piter, linktype=1):
    """Extract all packets belonging to the same flow from a pcap packet
    iterator."""
    first_ft = None

    for ts, raw in piter:
        ft = flowtuple_from_raw(raw, linktype)
        if not first_ft:
            first_ft = ft

        sip, dip, sport, dport, proto = ft
        if not (first_ft == ft or first_ft == (dip, sip, dport, sport, proto)):
            break

        yield {
            "src": sip, "dst": dip, "sport": sport, "dport": dport,
            "raw": payload_from_raw(raw, linktype).encode("base64"),
            "direction": first_ft == ft,
        }

def packets_for_stream(fobj, offset):
    """Open a PCAP, seek to a packet offset, then get all packets belonging to
    the same connection."""
    pcap = dpkt.pcap.Reader(fobj)
    pcapiter = iter(pcap)
    ts, raw = pcapiter.next()

    fobj.seek(offset)
    for p in next_connection_packets(pcapiter, linktype=pcap.datalink()):
        yield p
