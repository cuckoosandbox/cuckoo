#!/usr/bin/env python
# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import logging
import socket
import sys

try:
    from scapy.layers.dns import DNS, DNSQR, DNSRR
except ImportError:
    sys.exit("ERROR: Scapy library is missing (`pip install scapy`)")

def dns_serve(args):
    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udps.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udps.bind((args.bind, args.port))

    while True:
        data, addr = udps.recvfrom(1024)

        p = DNS(data)
        rp = DNS(id=p.id, qr=1, qdcount=p.qdcount, ancount=1, rcode=0)
        rp.qd = p[DNSQR]

        # IN A, actually look the domain up.
        if p.opcode == 0 and p[DNSQR].qtype == 1 and p[DNSQR].qclass == 1:
            if args.hardcode:
                answer_ip = args.hardcode
            else:
                try:
                    answer_ip = socket.gethostbyname(p.qd[0].qname)
                except:
                    if args.nxdomain:
                        answer_ip = args.nxdomain
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Small DNS server")
    parser.add_argument("--bind", help="IP address to bind for DNS and services.", default="0.0.0.0")
    parser.add_argument("--port", help="UDP port to bind for DNS and services.", default=53, type=int)
    parser.add_argument("--nxdomain", help="IP address to return instead of NXDOMAIN")
    parser.add_argument("--hardcode", help="Hardcoded IP address to return rather than actually doing DNS lookups")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)
    log = logging.getLogger("dnsserve")

    dns_serve(args)
