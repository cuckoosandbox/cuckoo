#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>

void send_tcp(const char *remote, const int port)
{
    int sd = socket(AF_INET, SOCK_STREAM, 0);
    assert(sd > 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(remote);
    addr.sin_port = htons(port);

    connect(sd, (struct sockaddr *)&addr , sizeof(addr));
    close(sd);
}

int main(int argc, char *argv[])
{
    send_tcp("127.0.0.1", 80);
    sleep(5);
    send_tcp("127.0.0.1", 80);

    return 0;
}
