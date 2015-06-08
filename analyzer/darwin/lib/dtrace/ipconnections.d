#!/usr/sbin/dtrace -C -s
#pragma D option quiet
/* ipconnections.d
 *
 * Copyright (C) 2015 Dmitry Rodionov
 * This software may be modified and distributed under the terms
 * of the MIT license. See the LICENSE file for details.
 *
 *
 * This script prints results in JSON format, where each entry is a dictionary:
 * {
 *     host        : string, // e.g. "192.168.0.1"
 *     host_port   : int,    // e.g. 49812
 *     remote      : string, // e.g. "8.8.8.8"
 *     remote_port : int,    // e.g. 80
 *     protocol    : string, // e.g. "TCP"
 *     timestamp   : int,    // e.g. 1433765405
 *     pid         : int     // e.g. 9213
 * }
 *
 */
#ifndef ANALYSIS_TIMEOUT
    #define ANALYSIS_TIMEOUT -1
#endif

dtrace:::BEGIN
{
    countdown = ANALYSIS_TIMEOUT;
}

ip:::receive
/pid == $target/
{
        this->protocol = args[2]->ip_ver == 4 ? args[4]->ipv4_protostr : args[5]->ipv6_nextstr;
        this->host = args[2]->ip_daddr;
        this->remote = args[2]->ip_saddr;
        /* Since the second argument (csinfo_t) is always filled with zeros [0],
         * the only way to get host and remote ports is to treat the third argument
         * as a raw pointer to struct ip and access stuff from there.
         *
         * Thanks to Quinn "The Eskimo!" from Apple DTS team for this trick!
         *
         * [0]:
         * From http://www.opensource.apple.com/source/xnu/xnu-2782.1.97/bsd/netinet/ip_output.c:
         * ------------------------------------------
         * DTRACE_IP6(send, struct mbuf *, m, struct inpcb *, NULL,
	     * struct ip *, ip, struct ifnet *, ifp,
	     * struct ip *, ip, struct ip6_hdr *, NULL);
         * ------------------------------------------
         * Note the NULL passed as a value for struct inpcb* (it will become
         * csinfo_t in dtrace).
         */
        this->host_port = ntohs(*(uint16_t *)(arg2 + 22));
        this->remote_port = ntohs(*(uint16_t *)(arg2 + 20));
        /* Convert walltimestamp to unix timestamp */
        this->timestamp = walltimestamp / 1000000000;

        printf("{\"host\":\"%s\", \"host_port\":%d, \"remote\":\"%s\", \"remote_port\":%d, \"protocol\":\"%s\", \"timestamp\": %d, \"pid\":%d}\n",
            this->host, this->host_port, this->remote, this->remote_port, this->protocol, this->timestamp, pid);
}
ip:::send
/pid == $target/
{
    this->protocol = args[2]->ip_ver == 4 ? args[4]->ipv4_protostr : args[5]->ipv6_nextstr;
    this->host = args[2]->ip_saddr;
    this->remote = args[2]->ip_daddr;
    this->host_port = ntohs(*(uint16_t *)(arg2 + 20));
    this->remote_port = ntohs(*(uint16_t *)(arg2 + 22));
    this->timestamp = walltimestamp / 1000000000;

    printf("{\"host\":\"%s\", \"host_port\":%d, \"remote\":\"%s\", \"remote_port\":%d, \"protocol\":\"%s\", \"timestamp\": %d, \"pid\":%d}\n",
        this->host, this->host_port, this->remote, this->remote_port, this->protocol, this->timestamp, pid);
}

profile:::tick-1sec
/countdown > 0/
{
    --countdown;
}

profile:::tick-1sec
/ countdown == 0 /
{
    exit(0);
}

dtrace:::END
{
    printf("## ipconnections.d done ##");
}
