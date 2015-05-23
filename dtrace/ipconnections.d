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
        this->host_port = ntohs(*((uint16_t *)(arg2 + 22)));
        this->remote_port = ntohs(*((uint16_t *)(arg2 + 20)));

        @num[this->host, this->host_port, this->remote, this->remote_port, this->protocol] = count();
}
ip:::send
/pid == $target/
{
    this->protocol = args[2]->ip_ver == 4 ? args[4]->ipv4_protostr : args[5]->ipv6_nextstr;
    this->host = args[2]->ip_saddr;
    this->remote = args[2]->ip_daddr;
    this->host_port = ntohs(*((uint16_t *)(arg2 + 20)));
    this->remote_port = ntohs(*((uint16_t *)(arg2 + 22)));

    @num[this->host, this->host_port, this->remote, this->remote_port, this->protocol] = count();
}


dtrace:::END
{
    printa("{\"host\":\"%s\", \"host_port\":%d, \"remote\":\"%s\", \"remote_port\":%d, \"protocol\":\"%s\", \"num\": %@d}\n", @num);
}
