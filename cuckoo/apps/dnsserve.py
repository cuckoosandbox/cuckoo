# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import socket
import sys

try:
    logging.getLogger("scapy.loading").setLevel(logging.ERROR)
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False

log = logging.getLogger("dnsserve")

def cuckoo_dnsserve(host, port, nxdomain, hardcode):
    if not HAVE_SCAPY:
        sys.exit(
            "Currently the DNS serve script is not available due to issues "
            "in upstream Scapy for Windows "
            "(https://github.com/secdev/scapy/issues/111)."
        )

    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udps.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udps.bind((host, port))

    while True:
        data, addr = udps.recvfrom(1024)

        p = DNS(data)
        rp = DNS(id=p.id, qr=1, qdcount=p.qdcount, ancount=1, rcode=0)
        rp.qd = p[DNSQR]

        # IN A, actually look the domain up.
        if p.opcode == 0 and p[DNSQR].qtype == 1 and p[DNSQR].qclass == 1:
            if hardcode:
                answer_ip = hardcode
            else:
                try:
                    answer_ip = socket.gethostbyname(p.qd[0].qname)
                except:
                    if nxdomain:
                        answer_ip = nxdomain
                    else:
                        rp.ancount = 0
                        rp.rcode = 3
                        answer_ip = None

            if answer_ip:
                rp.an = DNSRR(
                    rrname=p.qd[0].qname, ttl=60, rdlen=4, rdata=answer_ip
                )

                log.debug("IN A %s -> %s.", p.qd[0].qname, answer_ip)
        # IN PTR, we reply with NXDOMAIN.
        elif p.opcode == 0 and p[DNSQR].qtype == 12 and p[DNSQR].qclass == 1:
            rp.ancount = 0
            rp.rcode = 3
            log.info("IN PTR %s -> NXDOMAIN.", p.qd[0].qname)
        else:
            rp.ancount = 0
            rp.rcode = 2
            log.warn(
                "Unhandled query %s for %s/%s,%s - answering with servfail.",
                p.opcode, p.qd[0].qname, p[DNSQR].qtype, p[DNSQR].qclass
            )

        udps.sendto(rp.build(), addr)
