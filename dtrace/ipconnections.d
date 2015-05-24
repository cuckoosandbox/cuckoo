#!/usr/sbin/dtrace -s
#pragma D option quiet

dtrace:::BEGIN
{
    printf("## ipconnections.d ##\n");
}

ip:::receive
/pid == $target/
{
        this->protocol = args[2]->ip_ver == 4 ? args[4]->ipv4_protostr : args[5]->ipv6_nextstr;
        this->host = args[2]->ip_daddr;
        this->remote = args[2]->ip_saddr;
        /* The only way to get host and remote ports is to treat the third argument
         * as a raw pointer to struct ip and access stuff from there. */
        this->host_port = ntohs(*(uint16_t *)(arg2 + 22));
        this->remote_port = ntohs(*(uint16_t *)(arg2 + 20));
        /* Convert walltimestamp to unix timestamp */
        this->timestamp = walltimestamp / 1000000000;

        printf("{\"host\":\"%s\", \"host_port\":%d, \"remote\":\"%s\", \"remote_port\":%d, \"protocol\":\"%s\", \"timestamp\": %d}\n",
            this->host, this->host_port, this->remote, this->remote_port, this->protocol, this->timestamp);
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

    printf("{\"host\":\"%s\", \"host_port\":%d, \"remote\":\"%s\", \"remote_port\":%d, \"protocol\":\"%s\", \"timestamp\": %d}\n",
        this->host, this->host_port, this->remote, this->remote_port, this->protocol, this->timestamp);
}
