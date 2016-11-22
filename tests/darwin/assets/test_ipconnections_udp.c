#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

int main(int argc, char *argv[])
{
    int sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    assert(sd > 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    addr.sin_port = htons(53);

    char *request = "hi, i like you";
    int ret = sendto(sd, request, strlen(request), 0, (struct sockaddr*)&addr, sizeof(addr));
    assert(ret >= 0);

    close(sd);

    return EXIT_SUCCESS;
}
